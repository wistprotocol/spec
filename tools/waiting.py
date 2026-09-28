import copy
import hashlib

import catalogs
import collection_rules as rules
import items
import narrowing
import recovery_queue
import sealing
import tree_files

NOT_ADMITTED = "WIST2-E03"
MISMATCH = "WIST2-E04"
REGRESSED = "WIST2-E05"
TREE_REFUSED = tree_files.TreeRefusal.code
RECOVERY_KINDS = ("recovery_rotation", "reversal_recovery_rotation")
KIND_ORDER = ("removed", "page")


def refusal(check, *arguments):
    try:
        check(*arguments)
    except items.Refused as refused:
        return refused.code
    return None


def seconds(value):
    return narrowing.log_seconds(value)


class Site:
    def __init__(self, held, served):
        self.held = held
        self.served = served
        self.fetched = []

    def get(self, digest):
        if digest in self.held:
            return self.held[digest]
        self.fetched.append(digest)
        return self.served.get(digest)


class Aggregator:
    def __init__(self):
        self.log = sealing.Sealing()
        self.height = None
        self.parameters = None
        self.event = -1
        self.known = {}
        self.discovered = {}
        self.sealed = set()
        self.collections = {}
        self.lists = {}
        self.admission = {}
        self.payloads = {}
        self.tree = {}
        self.urls = {}
        self.windows = {}
        self.clock = None

    def latest_id(self, publisher, name):
        held = self.log.latest.get((publisher, name))
        return catalogs.catalog_id(held["envelope"]["catalog"]) if held is not None else None

    def collection(self, publisher, name):
        return self.collections.setdefault((publisher, name), {"accepted": None, "key": None, "failed_c1": False,
                                                               "c4_failed": False, "place": None,
                                                               "eligibility": None})

    def last_accepted(self, publisher, name):
        state = self.collections.get((publisher, name))
        if state is not None and state["accepted"] is not None and not state["failed_c1"]:
            return state["accepted"]
        return self.latest_id(publisher, name)

    def catalog_waits(self, publisher, name):
        state = self.collections.get((publisher, name))
        return (state is not None and state["accepted"] is not None and not state["failed_c1"]
                and not state["c4_failed"] and state["accepted"] != self.latest_id(publisher, name))

    def names_of(self, publisher):
        names = {name for p, name in self.collections if p == publisher}
        names |= {name for p, name in self.log.latest if p == publisher}
        return sorted(names, key=str.encode)

    def base_mode(self, publisher, name):
        accepted = self.last_accepted(publisher, name)
        if accepted is None or accepted == self.latest_id(publisher, name):
            return False
        return self.log.is_base(self.lists[accepted]["envelope"]["catalog"], self.parameters)

    def record_item(self, publisher, url, name, base):
        state = self.log.url_state(publisher, url)
        if state is None or state["state"] != "record":
            return None
        if base and state["collection"] == name:
            return None
        return state["item"]

    def i7_holds(self, publisher, name, item, base):
        record = self.record_item(publisher, item["url"], name, base)
        if items.kind(item) == "page":
            return record != items.item_id(item)
        return record is not None

    def waiting_urls(self, publisher):
        out = {}
        for name in self.names_of(publisher):
            accepted = self.last_accepted(publisher, name)
            if accepted is None:
                continue
            base = self.base_mode(publisher, name)
            statuses = self.admission[accepted]
            for index, item in enumerate(self.lists[accepted]["list"]):
                if statuses[item["url"]]["outcome"] == "admitted" and self.i7_holds(publisher, name, item, base):
                    out[item["url"]] = (name, index, item)
        return out

    def order_of(self, publisher, read):
        order = list(read)
        order += [name for name in self.names_of(publisher) if name not in order]
        return {name: i for i, name in enumerate(order)}

    def in_force_order(self, declaration):
        return [c["name"] for c in rules.collections_of(declaration)] if declaration is not None else []

    def refresh(self, publisher, eligibility, read):
        if publisher in self.windows:
            return
        now = self.waiting_urls(publisher)
        order = self.order_of(publisher, read)
        for slot in [s for s in self.urls if s[0] == publisher and s[1] not in now]:
            del self.urls[slot]
        for url, (name, index, item) in now.items():
            held = self.urls.get((publisher, url))
            if held is not None:
                held.update(collection=name, item=item)
            else:
                self.urls[(publisher, url)] = {"collection": name, "item": item,
                                               "place": [self.event, order[name], index],
                                               "eligibility": eligibility}

    def admission_replay(self, publisher, clock):
        held = self.log.replays.get(publisher)
        if held is not None:
            replay = copy.deepcopy(held)
        else:
            p = self.parameters
            replay = narrowing.Replay(p["recovery_window_days"], p["declaration_activation_epochs"],
                                      {k: p[k] for k in sealing.DECLARATION_PARAMETERS})
        if replay.window is not None and seconds(clock) >= replay.window["end"]:
            replay.current, replay.window = replay.window["chain_head"], None
        owner = None
        for found in self.discovered.get(publisher, []):
            if found["hash"] in self.sealed:
                continue
            transitions = []
            try:
                replay.apply(found["envelope"], self.height + 1, seconds(clock), transitions)
            except narrowing.HistoryRejected:
                continue
            if transitions and transitions[0]["kind"] in RECOVERY_KINDS:
                owner = found["envelope"]["publisher"]
        return replay, owner

    def no_pull(self, outcome):
        return {"outcome": outcome, "discovered": False, "reduces_authority": False, "sources": [], "window": False}

    def fetch_declaration(self, publisher, envelope, clock):
        if envelope is None:
            return self.no_pull("not_fetched"), None, False
        replay, owner = self.admission_replay(publisher, clock)
        transitions = []
        try:
            replay.apply(envelope, self.height + 1, seconds(clock), transitions)
        except narrowing.HistoryRejected as rejection:
            return self.no_pull(rejection.code), None, False
        kind = transitions[0]["kind"]
        inner = envelope["publisher"]
        digest = rules.declaration_hash(inner)
        self.known[digest] = inner
        if kind in RECOVERY_KINDS:
            owner = inner
        found = self.discovered.setdefault(publisher, [])
        discovered = kind != "idempotent" and digest not in self.sealed and all(f["hash"] != digest for f in found)
        predecessor = self.known.get(inner.get("prev_declaration"))
        reduces = predecessor is not None and rules.reduces_authority(predecessor, inner)
        if discovered:
            found.append({"hash": digest, "envelope": envelope, "reduces": reduces})
        if publisher in self.windows:
            sources, in_window = self.windows[publisher].sources(), True
        elif owner is not None:
            sources, in_window = [self.known[owner["prev_declaration"]], owner], False
        else:
            sources, in_window = ([replay.current] if replay.current is not None else []), False
        report = {"outcome": kind, "discovered": discovered, "reduces_authority": discovered and reduces,
                  "sources": [rules.declaration_hash(s) for s in sources], "window": in_window}
        return report, sources, in_window

    def judge_items(self, publisher, catalog, listed, sources, served_payloads, statuses, only=None):
        report = []
        for item in listed:
            url = item["url"]
            if only is not None and url not in only:
                continue
            codes = [refusal(items.judge_item, item, catalog, source, self.parameters) for source in sources]
            identifier = items.item_id(item)
            if not sources or all(code is not None for code in codes):
                status = {"outcome": "refused", "codes": sorted(set(codes))}
            elif items.kind(item) == "removed":
                status = {"outcome": "admitted", "payload": None}
            elif self.record_item(publisher, url, catalog["collection"], False) == identifier:
                status = {"outcome": "admitted", "payload": "record"}
            elif identifier in self.payloads:
                status = {"outcome": "admitted", "payload": "held"}
            else:
                payload = served_payloads.get(items.payload_name(item))
                if payload is None:
                    status = {"outcome": "not_admitted", "codes": [NOT_ADMITTED], "payload": "unavailable"}
                else:
                    code = refusal(items.judge_payload, item, payload, self.parameters)
                    if code is not None:
                        status = {"outcome": "not_admitted", "codes": [NOT_ADMITTED], "payload": "failed",
                                  "payload_code": code}
                    else:
                        self.payloads[identifier] = payload
                        status = {"outcome": "admitted", "payload": "fetched"}
            statuses[url] = status
            report.append({"url": url, "item": identifier, **status})
        return report

    def retry(self, publisher, catalog_id, sources, served):
        statuses = self.admission[catalog_id]
        listed = self.lists[catalog_id]["list"]
        pending = {url for url, status in statuses.items() if status["outcome"] != "admitted"}
        return self.judge_items(publisher, self.lists[catalog_id]["envelope"]["catalog"], listed, sources,
                                served.get("payloads", {}), statuses, pending)

    def pull_collection(self, publisher, name, position, sources, in_window, served):
        out = {"collection": name}
        if served is None:
            out["outcome"] = "unavailable"
            return out
        envelope = served["catalog"]
        code = refusal(catalogs.check_envelope_form, envelope)
        if code is not None:
            out.update(outcome="refused", codes=[code])
            return out
        catalog = envelope["catalog"]
        catalog_id = catalogs.catalog_id(catalog)
        out["catalog"] = catalog_id
        codes = set()
        if catalog["publisher"] != publisher or catalog["collection"] != name:
            codes.add(MISMATCH)
        window = self.windows.get(publisher) if in_window else None
        latest = self.latest_id(publisher, name)
        judged = [refusal(catalogs.judge_catalog, envelope, source, self.clock, self.parameters) for source in sources]
        passing = [source for source, code in zip(sources, judged) if code is None]
        key = recovery_queue.signing_key(envelope, passing[0]) if passing else None
        if window is not None:
            floor = self.log.latest.get((publisher, name))
            floor = catalogs.log_seconds(floor["envelope"]["catalog"]["generated_at"]) if floor else None
            order = "idempotent" if catalog_id == latest else (
                window.order(envelope, key, floor) if passing else "accepted")
            retry_sources = passing
        else:
            accepted = self.last_accepted(publisher, name)
            order = "accepted"
            if catalog_id in (accepted, latest):
                order = "idempotent"
            elif accepted is not None and catalogs.log_seconds(catalog["generated_at"]) <= catalogs.log_seconds(
                    self.lists[accepted]["envelope"]["catalog"]["generated_at"]):
                order = REGRESSED
            retry_sources = sources
        if order == "idempotent" and not codes:
            out.update(outcome="idempotent", tree_files_fetched=[],
                       items=self.retry(publisher, catalog_id, retry_sources, served) if retry_sources else [])
            return out
        if order == REGRESSED:
            codes.add(REGRESSED)
        if not passing:
            codes |= {code for code in judged if code is not None}
        if codes:
            out.update(outcome="refused", codes=sorted(codes))
            return out
        out["sources"] = [rules.declaration_hash(s) for s in passing]
        site = Site(self.tree, served.get("tree_files", {}))
        try:
            listed = tree_files.walk(catalog, site, self.parameters)
        except tree_files.TreeRefusal as refused:
            listed, reason = None, str(refused)
        for digest in site.fetched:
            octets = site.served.get(digest)
            if octets is not None and hashlib.sha256(octets).hexdigest() == digest:
                self.tree[digest] = octets
        out["tree_files_fetched"] = sorted(site.fetched)
        if listed is None:
            out.update(outcome="refused", codes=[TREE_REFUSED], reason=reason)
            return out
        base = self.log.is_base(catalog, self.parameters)
        present = {item["url"] for item in listed}
        dropped = [r["url"] for r in self.log.state()["records"]
                   if r["publisher"] == publisher and r["collection"] == name and r["url"] not in present
                   and any(rules.coverage(source, name, r["url"]) for source in sources)]
        if dropped and not base:
            out.update(outcome="refused", codes=[TREE_REFUSED], reason="the list drops the URL of a held record",
                       dropped=dropped)
            return out
        self.lists[catalog_id] = {"envelope": envelope, "list": listed}
        statuses = {}
        out.update(outcome="accepted", base=base, key=key)
        if window is not None:
            window.enqueue(name, key, {"catalog": catalog_id, "envelope": envelope, "place": [self.event, position]})
            out["queued"] = True
        else:
            state = self.collection(publisher, name)
            if self.catalog_waits(publisher, name):
                place, eligibility = state["place"], state["eligibility"]
            else:
                place, eligibility = [self.event, position], self.height + 1
            state.update(accepted=catalog_id, key=key, failed_c1=False, c4_failed=False, place=place,
                         eligibility=eligibility)
            out["queued"] = False
        self.admission[catalog_id] = statuses
        out["items"] = self.judge_items(publisher, catalog, listed, passing, served.get("payloads", {}), statuses)
        return out

    def pull(self, publisher, clock, envelope, served):
        if self.height is None:
            raise ValueError("the first event is an Epoch")
        self.event += 1
        self.clock = clock
        settlement = []
        window = self.windows.get(publisher)
        if window is not None and seconds(clock) >= window.end:
            settlement = self.settle_window(publisher, clock, self.parameters, self.height + 1)
        report, sources, in_window = self.fetch_declaration(publisher, envelope, clock)
        out = {"settlement": settlement, "declaration": report, "collections_pulled": [], "catalogs": []}
        if sources is None:
            return out
        names = []
        for source in sources:
            for collection in rules.collections_of(source):
                if collection["name"] not in names:
                    names.append(collection["name"])
        out["collections_pulled"] = names
        for position, name in enumerate(names):
            out["catalogs"].append(self.pull_collection(publisher, name, position, sources, in_window,
                                                        served.get(name)))
        self.refresh(publisher, self.height + 1, names)
        return out

    def reducing_pending(self, publisher, sealed):
        return [f["hash"] for f in self.discovered.get(publisher, []) if f["reduces"] and f["hash"] not in sealed]

    def settle_window(self, publisher, clock, parameters, eligibility):
        window = self.windows.pop(publisher)
        source = self.log.replays[publisher].window["chain_head"]
        settled, survivors = window.settle(source, clock, parameters)
        for name in window.names():
            state = self.collection(publisher, name)
            if name in survivors:
                state.update(accepted=survivors[name]["catalog"], key=survivors[name]["key"], failed_c1=False,
                             c4_failed=False, place=window.first[name], eligibility=eligibility)
            else:
                state.update(accepted=None, key=None, failed_c1=False, c4_failed=False, place=None,
                             eligibility=None)
        now = self.waiting_urls(publisher)
        order = self.order_of(publisher, self.in_force_order(source))
        for slot in [s for s in self.urls if s[0] == publisher]:
            del self.urls[slot]
        for url, (name, index, item) in now.items():
            if url in window.frozen:
                place = window.frozen[url]["place"]
            elif name in survivors:
                place = survivors[name]["place"] + [index]
            else:
                place = [self.event, order[name], index]
            self.urls[(publisher, url)] = {"collection": name, "item": item, "place": place,
                                           "eligibility": eligibility}
        return [{"publisher": publisher, **r} for r in settled]

    def settle(self, height, sealed_at, parameters):
        results = []
        for publisher, window in sorted(self.windows.items()):
            if seconds(sealed_at) >= window.end:
                results += self.settle_window(publisher, sealed_at, parameters, height)
        return results

    def open_windows(self):
        for publisher in sorted(self.log.replays):
            if not self.log.window_open(publisher) or publisher in self.windows:
                continue
            owner = self.log.replays[publisher].window["chain_head"]
            window = recovery_queue.Queue(self.known[owner["prev_declaration"]], owner,
                                          self.log.replays[publisher].window["end"])
            for (p, name), state in sorted(self.collections.items()):
                if p == publisher and self.catalog_waits(publisher, name):
                    window.enqueue(name, state["key"], {"catalog": state["accepted"],
                                                        "envelope": self.lists[state["accepted"]]["envelope"],
                                                        "place": state["place"]})
                    state.update(accepted=None, key=None, place=None, eligibility=None)
            for (p, url), entry in self.urls.items():
                if p == publisher:
                    window.frozen[url] = copy.deepcopy(entry)
                    entry["eligibility"] = None
            self.windows[publisher] = window

    def blocked(self, probe, sealed):
        out = {}
        for publisher in {p for p, _ in self.collections} | {p for p, _ in self.urls}:
            reasons = []
            if publisher in self.windows or probe.window_open(publisher):
                reasons.append("recovery_window")
            if self.reducing_pending(publisher, sealed):
                reasons.append("authority_reduction")
            out[publisher] = reasons
        return out

    def latest_fails_i4(self, probe, publisher, name, catalog_id):
        declaration = probe.declaration(publisher)
        if declaration is None or rules.collection_named(declaration, name) is None:
            return True
        return refusal(catalogs.binding, self.lists[catalog_id]["envelope"], declaration) is not None

    def plan(self, height, parameters, blocked, deferred_i4, probe):
        room, planned, deferred, sealed_names = {}, [], [], {}
        capacity = parameters["domain_epoch_entries_max"]
        waiting = sorted((state["place"], publisher, name) for (publisher, name), state in self.collections.items()
                         if self.catalog_waits(publisher, name) and state["eligibility"] <= height)
        for place, publisher, name in waiting:
            catalog_id = self.collections[(publisher, name)]["accepted"]
            ref = {"type": "publisher_catalog", "publisher": publisher, "collection": name, "catalog": catalog_id}
            reasons = list(blocked.get(publisher, []))
            if not reasons and room.get(publisher, capacity) == 0:
                reasons = ["capacity"]
            if reasons:
                deferred.append({**ref, "place": place, "reasons": reasons})
                continue
            room[publisher] = room.get(publisher, capacity) - 1
            sealed_names[(publisher, name)] = catalog_id
            planned.append((ref, {"type": "publisher_catalog", "body": self.lists[catalog_id]["envelope"]}))
        for kind in KIND_ORDER:
            candidates = sorted((entry["place"], publisher, url) for (publisher, url), entry in self.urls.items()
                                if items.kind(entry["item"]) == kind
                                and (entry["eligibility"] is None or entry["eligibility"] <= height))
            for place, publisher, url in candidates:
                entry = self.urls[(publisher, url)]
                name, item = entry["collection"], entry["item"]
                ref = {"type": "publisher_item", "publisher": publisher, "collection": name, "url": url,
                       "item": items.item_id(item)}
                reasons = list(blocked.get(publisher, []))
                if self.catalog_waits(publisher, name) and (publisher, name) not in sealed_names:
                    reasons.append("catalog_waiting")
                latest = sealed_names.get((publisher, name)) or self.latest_id(publisher, name)
                if latest is not None and ((publisher, name) in deferred_i4
                                           or self.latest_fails_i4(probe, publisher, name, latest)):
                    reasons.append("latest_fails_i4")
                if not reasons and room.get(publisher, capacity) == 0:
                    reasons = ["capacity"]
                if reasons:
                    deferred.append({**ref, "place": place, "reasons": reasons})
                    continue
                room[publisher] = room.get(publisher, capacity) - 1
                named = self.lists[latest]
                if named["envelope"]["catalog"]["root"] != self.lists[self.last_accepted(publisher, name)][
                        "envelope"]["catalog"]["root"]:
                    raise AssertionError("an Item planned against a latest Catalog of another root")
                body = items.publisher_item_body(item, named["envelope"]["catalog"], named["list"])
                planned.append(({**ref, "catalog": latest}, {"type": "publisher_item", "body": body}))
        return planned, deferred

    def epoch_input(self, height, sealed_at, parameters, entries):
        return {"height": height, "sealed_at": sealed_at, "parameters": parameters,
                "entries": sealing.canonical_order(entries)}

    def epoch(self, height, sealed_at, parameters, envelopes):
        if self.height is not None and height != self.height + 1:
            raise ValueError("Epochs must have consecutive heights")
        self.event += 1
        self.parameters = parameters
        settlement = self.settle(height, sealed_at, parameters)
        for envelope in envelopes:
            self.known[rules.declaration_hash(envelope["publisher"])] = envelope["publisher"]
        declarations = [{"type": "publisher_declaration", "body": e} for e in envelopes]
        sealed = self.sealed | {rules.declaration_hash(e["publisher"]) for e in envelopes}
        if any(not f["reduces"] and f["hash"] not in sealed for found in self.discovered.values() for f in found):
            raise ValueError("a discovered Declaration that does not reduce authority is sealed in the next Epoch")
        probe = copy.deepcopy(self.log)
        if probe.epoch(self.epoch_input(height, sealed_at, parameters, declarations))["status"] != "accepted":
            raise ValueError("the Epoch's Declarations do not replay")
        blocked = self.blocked(probe, sealed)
        deferred_i4, left = set(), []
        while True:
            planned, deferred = self.plan(height, parameters, blocked, deferred_i4, probe)
            entries = declarations + [entry for _, entry in planned]
            ordered = sealing.canonical_order(entries)
            trial = copy.deepcopy(self.log)
            result = trial.epoch(self.epoch_input(height, sealed_at, parameters, entries))
            if result["status"] != "accepted":
                raise AssertionError(result)
            failures = []
            for entry, disposition in zip(ordered, result["entries"]):
                if disposition is not None and disposition["disposition"] != "valid":
                    ref = next(ref for ref, e in planned if e is entry)
                    failures.append((ref, disposition))
            if not failures:
                break
            touched = set()
            failed_catalogs = {ref["catalog"] for ref, _ in failures if ref["type"] == "publisher_catalog"}
            for ref, disposition in failures:
                if ref["type"] == "publisher_item" and ref["catalog"] in failed_catalogs:
                    continue
                failed, codes = disposition["failed"], disposition["codes"]
                publisher, name = ref["publisher"], ref["collection"]
                if ref["type"] == "publisher_catalog":
                    turn = (0, self.collections[(publisher, name)]["place"])
                else:
                    entry = self.urls[(publisher, ref["url"])]
                    turn = (1 + KIND_ORDER.index(items.kind(entry["item"])), entry["place"])
                touched.add(publisher)
                if ref["type"] == "publisher_catalog":
                    state = self.collections[(publisher, name)]
                    if "C1" in failed:
                        state["failed_c1"] = True
                        left.append((turn, {**ref, "condition": "C1", "codes": codes, "reported": True}))
                    elif failed == ["C4"]:
                        state["c4_failed"] = True
                        left.append((turn, {**ref, "condition": "C4", "codes": codes, "reported": False}))
                    else:
                        raise AssertionError((ref, disposition))
                elif "I4" in failed:
                    deferred_i4.add((publisher, name))
                elif failed == ["I5"]:
                    accepted = self.last_accepted(publisher, name)
                    self.admission[accepted][ref["url"]] = {"outcome": "refused", "codes": codes, "at_turn": True}
                    left.append((turn, {**{k: v for k, v in ref.items() if k != "catalog"}, "condition": "I5",
                                        "codes": codes, "reported": True}))
                else:
                    raise AssertionError((ref, disposition))
            for publisher in sorted(touched):
                self.refresh(publisher, height + 1, self.in_force_order(probe.declaration(publisher)))
        epoch = self.epoch_input(height, sealed_at, parameters, entries)
        result = self.log.epoch(epoch)
        if result["status"] != "accepted" or any(
                d is not None and d["disposition"] != "valid" for d in result["entries"]):
            raise AssertionError(result)
        if self.log.state() != trial.state():
            raise AssertionError("the sealed state differs from the planned one")
        self.height = height
        self.sealed = sealed
        maximum = parameters["max_inclusion_epochs"]
        for publisher in sorted({p for p, _ in self.collections} | {p for p, _ in self.urls}):
            self.refresh(publisher, height + 1, self.in_force_order(self.log.declaration(publisher)))
        self.open_windows()
        for (publisher, name), state in self.collections.items():
            if self.catalog_waits(publisher, name):
                state["eligibility"] = height + 1
            else:
                state.update(place=None, eligibility=None)
        for (publisher, url), entry in self.urls.items():
            if publisher not in self.windows:
                entry["eligibility"] = height + 1
        return {"settlement": settlement, "entries": epoch["entries"],
                "sealed": [{**ref, "eligibility": height, "ceiling": height + maximum} for ref, _ in planned],
                "left": [entry for _, entry in sorted(left, key=lambda pair: pair[0])], "deferred": deferred, "records_removed": result["records_removed"]}

    def state(self):
        maximum = self.parameters["max_inclusion_epochs"]

        def ceiling(eligibility):
            return None if eligibility is None else eligibility + maximum

        keys = sorted(set(self.collections) | set(self.log.latest), key=lambda k: (k[0].encode(), k[1].encode()))
        collections = []
        for publisher, name in keys:
            waiting = None
            if self.catalog_waits(publisher, name):
                state = self.collections[(publisher, name)]
                waiting = {"catalog": state["accepted"], "place": state["place"],
                           "eligibility": state["eligibility"], "ceiling": ceiling(state["eligibility"])}
            collections.append({"publisher": publisher, "collection": name,
                                "latest": self.latest_id(publisher, name),
                                "last_accepted": self.last_accepted(publisher, name), "waiting": waiting})
        urls = [{"publisher": publisher, "url": url, "collection": entry["collection"],
                 "item": items.item_id(entry["item"]), "place": entry["place"],
                 "eligibility": entry["eligibility"], "ceiling": ceiling(entry["eligibility"])}
                for (publisher, url), entry in sorted(self.urls.items(),
                                                      key=lambda kv: (kv[1]["place"], kv[0][0].encode()))]
        queue = [{"publisher": publisher, "collection": name, "key": key, "catalog": entry["catalog"],
                  "place": entry["place"], "first_place": window.first[name]}
                 for publisher, window in sorted(self.windows.items())
                 for (name, key), entry in sorted(window.held.items(), key=lambda kv: (kv[1]["place"], kv[0][1]))]
        reductions = [{"publisher": publisher, "declaration": digest}
                      for publisher in sorted(self.discovered)
                      for digest in self.reducing_pending(publisher, self.sealed)]
        records = [{"publisher": r["publisher"], "url": r["url"], "collection": r["collection"], "item": r["item"],
                    "catalog": r["catalog"]} for r in self.log.state()["records"]]
        return {"collections": collections, "urls": urls, "queue": queue, "reductions_pending": reductions,
                "records": records}
