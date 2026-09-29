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
REVERSAL_KINDS = ("reversal_ordinary_rotation", "reversal_recovery_rotation")
PENDING_KINDS = ("fresh_identity_pending", "pending_replacement")
NOT_DISCOVERED = ("idempotent", "recovery_chain_head")
KIND_ORDER = ("removed", "page")


def refusal(check, *arguments):
    try:
        check(*arguments)
    except items.Refused as refused:
        return refused.code
    return None


def seconds(value):
    return narrowing.log_seconds(value)


def place_key(place, publisher):
    return place[0], publisher.encode(), place[1:]


def registrable_domain(host, suffix_rules):
    if suffix_rules is None:
        return host
    labels = host.split(".")
    matching = []
    for rule in suffix_rules:
        exception = rule.startswith("!")
        parts = (rule[1:] if exception else rule).split(".")
        if len(parts) <= len(labels) and all(
                part == "*" or part == label for part, label in zip(reversed(parts), reversed(labels))):
            matching.append((exception, parts))
    exceptions = [parts for exception, parts in matching if exception]
    if exceptions:
        size = len(max(exceptions, key=len)) - 1
    elif matching:
        size = max(len(parts) for _, parts in matching)
    else:
        size = 1
    if len(labels) <= size:
        return host
    return ".".join(labels[-(size + 1):])


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
    def __init__(self, suffix_rules=None):
        self.log = sealing.Sealing()
        self.suffix_rules = suffix_rules
        self.height = None
        self.parameters = None
        self.event = -1
        self.known = {}
        self.discovered = {}
        self.floors = {}
        self.sealed = set()
        self.collections = {}
        self.lists = {}
        self.admission = {}
        self.payloads = {}
        self.tree = {}
        self.urls = {}
        self.windows = {}
        self.clock = None

    def unit(self, publisher):
        return registrable_domain(publisher, self.suffix_rules)

    def latest_id(self, publisher, name):
        held = self.log.latest.get((publisher, name))
        return catalogs.catalog_id(held["envelope"]["catalog"]) if held is not None else None

    def inner(self, catalog_id):
        return self.lists[catalog_id]["envelope"]["catalog"] if catalog_id is not None else None

    def collection(self, publisher, name):
        return self.collections.setdefault((publisher, name), {"accepted": None, "envelope": None, "key": None,
                                                               "failed_c1": False, "c4_failed": False,
                                                               "place": None, "eligibility": None})

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
        return self.log.is_base(self.inner(accepted))

    def record_item(self, publisher, url, name, base):
        state = self.log.url_state(publisher, url)
        if state is None or state["state"] != "record":
            return None
        if base and state["collection"] == name:
            return None
        return state["item"]

    def withdrawn(self, item):
        return items.kind(item) == "page" and items.item_id(item) in self.log.withdrawals

    def i7_holds(self, publisher, name, item, base):
        record = self.record_item(publisher, item["url"], name, base)
        if items.kind(item) == "page":
            return record != items.item_id(item) and not self.withdrawn(item)
        return record is not None

    def waiting_urls(self, publisher, declaration=None):
        if declaration is None:
            declaration = self.log.declaration(publisher)
        out, order = {}, {}
        for name in self.names_of(publisher):
            accepted = self.last_accepted(publisher, name)
            if accepted is None:
                continue
            base = self.base_mode(publisher, name)
            statuses = self.admission[accepted]
            for index, item in enumerate(self.lists[accepted]["list"]):
                url = item["url"]
                covered = declaration is not None and rules.coverage(declaration, name, url)
                rank = (covered, recovery_queue.order_key({"envelope": {"catalog": self.inner(accepted)}}))
                if (statuses[url]["outcome"] == "admitted" and self.i7_holds(publisher, name, item, base)
                        and (url not in order or rank > order[url])):
                    out[url], order[url] = (name, index, item), rank
        return out

    def no_longer_record(self, publisher, name, url):
        accepted = self.last_accepted(publisher, name)
        if accepted is None:
            return None
        statuses = self.admission[accepted]
        for item in self.lists[accepted]["list"]:
            if item["url"] == url and statuses[url]["outcome"] == "admitted" and not self.i7_holds(
                    publisher, name, item, self.base_mode(publisher, name)):
                return item
        return None

    def place_order(self, publisher, declaration, pulled=()):
        named = [c["name"] for c in rules.collections_of(declaration)] if declaration is not None else []
        rest = sorted((set(self.names_of(publisher)) | set(pulled)) - set(named), key=str.encode)
        return {name: i for i, name in enumerate(named + rest)}

    def window_opened(self, publisher):
        return publisher in self.windows and self.windows[publisher].opened

    def refresh(self, publisher, eligibility, order, declaration=None):
        if self.window_opened(publisher):
            return
        now = self.waiting_urls(publisher, declaration)
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

    def descendants(self, publisher, hashes):
        out = set(hashes)
        for found in self.discovered.get(publisher, []):
            if found["envelope"]["publisher"].get("prev_declaration") in out:
                out.add(found["hash"])
        return out

    def drop_discovered(self, publisher, hashes):
        gone = self.descendants(publisher, hashes)
        self.discovered[publisher] = [f for f in self.discovered.get(publisher, []) if f["hash"] not in gone]
        for found in self.discovered[publisher]:
            if found.get("discarded_by") in gone:
                del found["discarded_by"]
        if not self.discovered[publisher] and self.log.declaration(publisher) is None:
            self.floors.pop(publisher, None)
        return gone

    def supersede(self, publisher):
        self.drop_discovered(publisher, {f["hash"] for f in self.discovered.get(publisher, [])
                                         if f["kind"] == "in_window_competitor"})

    def discard_pending(self, publisher, reversal):
        for found in self.discovered.get(publisher, []):
            if found["kind"] in PENDING_KINDS and found["hash"] not in self.sealed:
                found.setdefault("discarded_by", reversal)

    def admission_replay(self, publisher, clock):
        held = self.log.replays.get(publisher)
        if held is not None:
            replay = copy.deepcopy(held)
        else:
            p = self.parameters
            replay = narrowing.Replay(p["recovery_window_days"], p["declaration_activation_epochs"], None)
        replay.parameters = dict(rules.UNREAD_PARAMETERS)
        if replay.window is not None and seconds(clock) >= replay.window["end"]:
            replay.current, replay.window = replay.window["chain_head"], None
            self.supersede(publisher)
        for found in self.discovered.get(publisher, []):
            try:
                replay.apply(found["envelope"], self.height + 1, seconds(clock), [])
            except narrowing.HistoryRejected:
                continue
        if replay.floor is not None:
            replay.floor = max(replay.floor, self.floors.get(publisher, 0))
        return replay

    def no_pull(self, outcome):
        return {"outcome": outcome, "discovered": False, "reduces_authority": False, "sources": [], "window": False}

    def fetch_declaration(self, publisher, envelope, clock, parameters):
        if envelope is None:
            return self.no_pull("not_fetched"), None, None
        replay = self.admission_replay(publisher, clock)
        replay.parameters = {k: parameters[k] for k in sealing.DECLARATION_PARAMETERS}
        transitions = []
        try:
            replay.fetch(envelope, self.height + 1, seconds(clock), transitions)
        except narrowing.HistoryRejected as rejection:
            return self.no_pull(rejection.code), None, None
        kind = transitions[0]["kind"]
        inner = envelope["publisher"]
        digest = rules.declaration_hash(inner)
        self.known[digest] = inner
        found = self.discovered.setdefault(publisher, [])
        discovered = kind not in NOT_DISCOVERED and digest not in self.sealed and all(f["hash"] != digest for f in found)
        predecessor = self.known.get(inner.get("prev_declaration"))
        reduces = predecessor is not None and rules.reduces_authority(predecessor, inner)
        if discovered:
            if kind in REVERSAL_KINDS:
                self.discard_pending(publisher, digest)
            self.discovered[publisher].append({"hash": digest, "envelope": envelope, "reduces": reduces,
                                               "kind": kind})
            self.floors[publisher] = max(self.floors.get(publisher, 0), inner["seq"])
        sources = replay.sources()
        if publisher not in self.windows and len(sources) == 2:
            self.windows[publisher] = recovery_queue.Queue(sources[0], sources[1], None)
        mode = "window" if publisher in self.windows else "single"
        report = {"outcome": kind, "discovered": discovered, "reduces_authority": discovered and reduces,
                  "sources": [rules.declaration_hash(s) for s in sources], "window": self.window_opened(publisher)}
        return report, sources, mode

    def check_payload(self, item, payload, parameters):
        if payload is None:
            return {"outcome": "not_admitted", "codes": [NOT_ADMITTED], "payload": "unavailable"}
        code = refusal(items.judge_payload, item, payload, parameters)
        if code is not None:
            return {"outcome": "not_admitted", "codes": [NOT_ADMITTED], "payload": "failed", "payload_code": code}
        return None

    def judge_items(self, publisher, catalog, listed, sources, served_payloads, statuses, parameters, only=None):
        report = []
        for item in listed:
            url = item["url"]
            if only is not None and url not in only:
                continue
            codes = [refusal(items.judge_item, item, catalog, source, parameters) for source in sources]
            identifier = items.item_id(item)
            form = refusal(items.check_item_form, item)
            if form is None and self.withdrawn(item):
                status = {"outcome": "not_admitted", "codes": [NOT_ADMITTED], "payload": "withdrawn"}
            elif not sources or all(code is not None for code in codes):
                status = {"outcome": "refused", "codes": sorted(set(codes))}
            elif items.kind(item) == "removed":
                status = {"outcome": "admitted", "payload": None}
            elif self.record_item(publisher, url, catalog["collection"], False) == identifier:
                status = {"outcome": "admitted", "payload": "record"}
            elif identifier in self.payloads:
                status = self.check_payload(item, self.payloads[identifier], parameters) or {
                    "outcome": "admitted", "payload": "held"}
            else:
                payload = served_payloads.get(items.payload_name(item))
                status = self.check_payload(item, payload, parameters)
                if status is None:
                    self.payloads[identifier] = payload
                    status = {"outcome": "admitted", "payload": "fetched"}
            statuses[url] = status
            report.append({"url": url, "item": identifier, **status})
        return report

    def retry(self, publisher, catalog_id, sources, served, parameters):
        statuses = self.admission[catalog_id]
        listed = self.lists[catalog_id]["list"]
        pending = {url for url, status in statuses.items() if status["outcome"] != "admitted"}
        return self.judge_items(publisher, self.inner(catalog_id), listed, sources, served.get("payloads", {}),
                                statuses, parameters, pending)

    def discovery_order(self, publisher, name, catalog, catalog_id, key):
        if not self.catalog_waits(publisher, name):
            return "idempotent" if catalog_id == self.latest_id(publisher, name) else None
        state = self.collections[(publisher, name)]
        if state["key"] != key:
            return None
        if catalog_id == state["accepted"]:
            return "idempotent"
        waiting_at = catalogs.log_seconds(self.inner(state["accepted"])["generated_at"])
        if catalogs.log_seconds(catalog["generated_at"]) <= waiting_at:
            return REGRESSED
        return None

    def pull_collection(self, publisher, name, position, sources, mode, served, parameters):
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
        latest = self.latest_id(publisher, name)
        judged = [refusal(catalogs.judge_catalog, envelope, source, self.clock, parameters) for source in sources]
        passing = [source for source, code in zip(sources, judged) if code is None]
        key = recovery_queue.signing_key(envelope, passing[0]) if passing else None
        if not passing:
            codes |= {code for code in judged if code is not None}
        if codes:
            out.update(outcome="refused", codes=sorted(codes))
            return out
        held_floor = self.log.latest.get((publisher, name))
        floor = catalogs.log_seconds(held_floor["envelope"]["catalog"]["generated_at"]) if held_floor else None
        if mode == "window":
            window = self.windows[publisher]
            waiting_order = None if window.opened else self.discovery_order(publisher, name, catalog, catalog_id, key)
            order = "idempotent" if catalog_id == latest else waiting_order or window.order(envelope, key, floor)
        else:
            order = catalogs.pull_order(catalog, {"publisher": catalog["publisher"], "collection": catalog["collection"]},
                                        self.inner(self.last_accepted(publisher, name)),
                                        held_floor["envelope"]["catalog"] if held_floor else None)
        if order == "idempotent":
            out.update(outcome="idempotent", tree_files_fetched=[],
                       items=self.retry(publisher, catalog_id, passing, served, parameters))
            return out
        if order == REGRESSED:
            out.update(outcome="refused", codes=[REGRESSED])
            return out
        out["sources"] = [rules.declaration_hash(s) for s in passing]
        site = Site(self.tree, served.get("tree_files", {}))
        try:
            listed = tree_files.walk(catalog, site, parameters)
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
        base = self.log.is_base(catalog)
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
        if mode == "window":
            self.windows[publisher].enqueue(name, key, {"catalog": catalog_id, "envelope": envelope,
                                                        "place": [self.event, position]})
            out["queued"] = True
        else:
            state = self.collection(publisher, name)
            if self.catalog_waits(publisher, name):
                place, eligibility = state["place"], state["eligibility"]
            else:
                place, eligibility = [self.event, position], self.height + 1
            state.update(accepted=catalog_id, envelope=envelope, key=key, failed_c1=False, c4_failed=False,
                         place=place, eligibility=eligibility)
            out["queued"] = False
        self.admission[catalog_id] = statuses
        out["items"] = self.judge_items(publisher, catalog, listed, passing, served.get("payloads", {}), statuses,
                                        parameters)
        return out

    def pull(self, publisher, clock, envelope, served, parameters=None):
        if self.height is None:
            raise ValueError("the first event is an Epoch")
        parameters = sealing.check_parameters(parameters if parameters is not None else self.parameters)
        self.event += 1
        self.clock = clock
        settlement = []
        window = self.windows.get(publisher)
        if window is not None and window.opened and seconds(clock) >= window.end:
            head = self.admission_replay(publisher, clock).current
            settlement = self.settle_window(publisher, clock, parameters, self.height + 1, order_declaration=head)
            self.event += 1
        report, sources, mode = self.fetch_declaration(publisher, envelope, clock, parameters)
        settlement += self.settle_orphans(clock, parameters, self.height + 1)
        if sources is not None and publisher not in self.windows:
            mode = "single"
        out = {"settlement": settlement, "declaration": report, "collections_pulled": [], "catalogs": []}
        if sources is None:
            return out
        names = narrowing.collection_names(sources)
        out["collections_pulled"] = names
        order = self.place_order(publisher, sources[0] if sources else None, names)
        for name in names:
            out["catalogs"].append(self.pull_collection(publisher, name, order[name], sources, mode,
                                                        served.get(name), parameters))
        if mode != "window":
            self.refresh(publisher, self.height + 1, self.place_order(publisher, sources[0] if sources else None,
                                                                      names))
        if not (report["discovered"] or any(c["outcome"] == "accepted" for c in out["catalogs"]) or any(
                i["outcome"] == "admitted" for c in out["catalogs"] for i in c.get("items", []))):
            out["noise"] = True
        return out

    def reducing_pending(self, publisher, sealed):
        return [f["hash"] for f in self.discovered.get(publisher, []) if f["reduces"] and f["hash"] not in sealed]

    def settle_orphans(self, clock, parameters, eligibility):
        results = []
        for publisher, window in sorted(self.windows.items()):
            owner = rules.declaration_hash(window.owner)
            if window.opened or owner in self.sealed or any(
                    f["hash"] == owner for f in self.discovered.get(publisher, [])):
                continue
            self.absorb(publisher, window)
            results += self.settle_window(publisher, clock, parameters, eligibility, self.log.declaration(publisher),
                                          keep=True)
        return results

    def settle_window(self, publisher, clock, parameters, eligibility, source=None, keep=False,
                      order_declaration=None):
        window = self.windows.pop(publisher)
        if source is None:
            source = self.log.replays[publisher].window["chain_head"]
        floors = {name: catalogs.log_seconds(held["envelope"]["catalog"]["generated_at"])
                  for (p, name), held in self.log.latest.items() if p == publisher}
        settled, survivors = window.settle(source, clock, parameters, floors)
        for name in sorted(set(window.names()) | set(self.names_of(publisher)), key=str.encode):
            state = self.collection(publisher, name)
            if name in survivors:
                kept = window.waited.get(name) if keep else None
                state.update(accepted=survivors[name]["catalog"], envelope=survivors[name]["envelope"],
                             key=survivors[name]["key"], failed_c1=False, c4_failed=False, place=window.first[name],
                             eligibility=kept if kept is not None else eligibility)
            else:
                state.update(accepted=None, envelope=None, key=None, failed_c1=False, c4_failed=False, place=None,
                             eligibility=None)
        self.supersede(publisher)
        leaves_current = order_declaration if order_declaration is not None else source
        now = self.waiting_urls(publisher, leaves_current)
        order = self.place_order(publisher, leaves_current)
        for slot in [s for s in self.urls if s[0] == publisher]:
            del self.urls[slot]
        for url, (name, index, item) in now.items():
            url_eligibility = eligibility
            if url in window.frozen:
                place = window.frozen[url]["place"]
                if keep:
                    url_eligibility = window.frozen[url]["eligibility"]
            elif name in survivors:
                place = survivors[name]["place"] + [index]
            else:
                place = [self.event, order[name], index]
            self.urls[(publisher, url)] = {"collection": name, "item": item, "place": place,
                                           "eligibility": url_eligibility}
        return [{"publisher": publisher, **r} for r in settled]

    def settle(self, height, sealed_at, parameters):
        results = []
        for publisher, window in sorted(self.windows.items()):
            if window.opened and seconds(sealed_at) >= window.end:
                results += self.settle_window(publisher, sealed_at, parameters, height)
        for publisher, replay in sorted(self.log.replays.items()):
            if replay.window is not None and seconds(sealed_at) >= replay.window["end"]:
                self.supersede(publisher)
        return results

    def absorb(self, publisher, window):
        for (p, name), state in sorted(self.collections.items()):
            if p == publisher and self.catalog_waits(publisher, name):
                window.waited[name] = state["eligibility"]
                window.enqueue(name, state["key"], {"catalog": state["accepted"], "envelope": state["envelope"],
                                                    "place": state["place"]})
                state.update(accepted=None, envelope=None, key=None, place=None, eligibility=None)
        for (p, url), entry in self.urls.items():
            if p == publisher:
                window.frozen[url] = copy.deepcopy(entry)
                entry["eligibility"] = None

    def open_windows(self):
        for publisher in sorted(self.log.replays):
            if not self.log.window_open(publisher) or self.window_opened(publisher):
                continue
            opened = self.log.replays[publisher].window
            window = self.windows.get(publisher) or recovery_queue.Queue(opened["before"], opened["owner"], None)
            window.before, window.owner = opened["before"], opened["owner"]
            window.open(opened["end"])
            self.absorb(publisher, window)
            self.windows[publisher] = window

    def publishers(self):
        return {p for p, _ in self.collections} | {p for p, _ in self.urls}

    def window_blocks(self, probe, publisher):
        return self.window_opened(publisher) or probe.window_open(publisher)

    def latest_fails_i4(self, probe, publisher, name, envelope):
        declaration = probe.declaration(publisher)
        if declaration is None or rules.collection_named(declaration, name) is None:
            return True
        return refusal(catalogs.binding, envelope, declaration) is not None

    def plan(self, height, parameters, held, deferred_i4, probe, gone):
        room, planned, deferred, holding, sealed_names, deferred_names, dropped = {}, [], [], [], {}, set(), []
        capacity = parameters["domain_epoch_entries_max"]

        def free(publisher):
            return room.get(self.unit(publisher), capacity)

        def take(publisher):
            room[self.unit(publisher)] = free(publisher) - 1

        waiting = sorted(((state["place"], publisher, name) for (publisher, name), state in self.collections.items()
                          if self.catalog_waits(publisher, name) and state["eligibility"] <= height),
                         key=lambda t: (place_key(t[0], t[1]), t[2].encode()))
        for place, publisher, name in waiting:
            state = self.collections[(publisher, name)]
            catalog_id = state["accepted"]
            ref = {"type": "publisher_catalog", "publisher": publisher, "collection": name, "catalog": catalog_id}
            reasons = ["recovery_window"] if self.window_blocks(probe, publisher) else []
            if not reasons and publisher in held:
                holding.append({**ref, "place": place, "reasons": ["authority_reduction"],
                                "eligibility": state["eligibility"]})
                continue
            if not reasons and free(publisher) == 0:
                reasons = ["capacity"]
            if reasons:
                deferred.append({**ref, "place": place, "reasons": reasons})
                deferred_names.add((publisher, name))
                continue
            take(publisher)
            sealed_names[(publisher, name)] = (catalog_id, state["envelope"])
            planned.append((ref, {"type": "publisher_catalog", "body": state["envelope"]}, state["eligibility"]))
        for kind in KIND_ORDER:
            candidates = sorted(((entry["place"], publisher, url) for (publisher, url), entry in self.urls.items()
                                 if items.kind(entry["item"]) == kind and (publisher, url) not in gone
                                 and (entry["eligibility"] is None or entry["eligibility"] <= height)),
                                key=lambda t: (place_key(t[0], t[1]), t[2].encode()))
            for place, publisher, url in candidates:
                entry = self.urls[(publisher, url)]
                name, item = entry["collection"], entry["item"]
                ref = {"type": "publisher_item", "publisher": publisher, "collection": name, "url": url,
                       "item": items.item_id(item)}
                reasons = ["recovery_window"] if self.window_blocks(probe, publisher) else []
                catalog_unsealed = self.catalog_waits(publisher, name) and (publisher, name) not in sealed_names
                if not reasons and catalog_unsealed and (publisher, name) in deferred_names:
                    reasons.append("catalog_waiting")
                held_latest = self.log.latest.get((publisher, name))
                latest, latest_envelope = sealed_names.get((publisher, name)) or (
                    (self.latest_id(publisher, name), held_latest["envelope"]) if held_latest else (None, None))
                undeferred_catalog = catalog_unsealed and (publisher, name) not in deferred_names
                if (reasons != ["recovery_window"] and not undeferred_catalog and latest is not None
                        and ((publisher, name) in deferred_i4
                             or self.latest_fails_i4(probe, publisher, name, latest_envelope))):
                    reasons.append("latest_fails_i4")
                if not reasons and (publisher in held or catalog_unsealed):
                    holding.append({**ref, "place": place, "eligibility": entry["eligibility"],
                                    "reasons": ["authority_reduction"] if publisher in held else ["catalog_waiting"]})
                    continue
                if not reasons and free(publisher) == 0:
                    reasons = ["capacity"]
                if reasons:
                    deferred.append({**ref, "place": place, "reasons": reasons})
                    continue
                accepted = self.last_accepted(publisher, name)
                status = self.admission[accepted][url]
                if kind == "page":
                    failed = self.check_payload(item, self.payloads.get(items.item_id(item)), parameters)
                    if failed is not None:
                        self.admission[accepted][url] = {**failed, "at_epoch": True}
                        gone.add((publisher, url))
                        dropped.append((place_key(place, publisher), {
                            **ref, "condition": "payload", "codes": [NOT_ADMITTED], "reported": True,
                            **({"payload_code": failed["payload_code"]} if "payload_code" in failed else {})}))
                        continue
                take(publisher)
                named = self.lists[latest]
                body = items.publisher_item_body(item, named["envelope"]["catalog"], named["list"])
                planned.append(({**ref, "catalog": latest}, {"type": "publisher_item", "body": body},
                                entry["eligibility"]))
        return planned, deferred, holding, dropped

    def waiting_after_catalogs(self, publisher, url, height, sealed_at, parameters, declarations, planned, probe):
        after = copy.deepcopy(self.log)
        catalog_entries = [entry for _, entry, _ in planned if entry["type"] == "publisher_catalog"]
        after.epoch(self.epoch_input(height, sealed_at, parameters, declarations + catalog_entries))
        held, self.log = self.log, after
        try:
            return self.waiting_urls(publisher, probe.declaration(publisher)).get(url)
        finally:
            self.log = held

    def epoch_input(self, height, sealed_at, parameters, entries):
        return {"height": height, "sealed_at": sealed_at, "parameters": parameters,
                "entries": sealing.canonical_order(entries)}

    def descendants_of(self, digest, envelopes):
        chain = {digest}
        known = [f["envelope"] for found in self.discovered.values() for f in found] + list(envelopes)
        changed = True
        while changed:
            changed = False
            for envelope in known:
                inner = envelope["publisher"]
                own = rules.declaration_hash(inner)
                if own not in chain and inner.get("prev_declaration") in chain:
                    chain.add(own)
                    changed = True
        return chain

    def candidate_checks(self, envelopes, parameters):
        read = {k: parameters[k] for k in sealing.DECLARATION_PARAMETERS}
        failed = {}
        for envelope in envelopes:
            try:
                rules.validate_declaration(envelope, read)
            except rules.RuleViolation as violation:
                failed[rules.declaration_hash(envelope["publisher"])] = violation.code
        if not failed:
            return envelopes, [], []
        cause = {}
        for digest, code in sorted(failed.items()):
            for descendant in self.descendants_of(digest, envelopes):
                cause.setdefault(descendant, code)
        for publisher in sorted(self.discovered):
            self.drop_discovered(publisher, set(failed))
        reports = [{"declaration": digest, "code": code} for digest, code in sorted(failed.items())]
        left = [{"declaration": digest, "names": self.known[digest]["prev_declaration"], "code": cause[digest]}
                for digest in sorted(set(cause) - set(failed))]
        kept = [e for e in envelopes if rules.declaration_hash(e["publisher"]) not in cause]
        return kept, reports, left

    def epoch(self, height, sealed_at, parameters, envelopes, updates=(), late=()):
        if self.height is not None and height != self.height + 1:
            raise ValueError("Epochs must have consecutive heights")
        parameters = sealing.check_parameters(parameters)
        self.event += 1
        self.parameters = parameters
        settlement = self.settle(height, sealed_at, parameters)
        for envelope in envelopes:
            self.known[rules.declaration_hash(envelope["publisher"])] = envelope["publisher"]
        sealed_updates, refused_updates = [], []
        for update in updates:
            named = update["update"]["details"]["delta_id"]
            if update["update"]["subject"] in self.log.sealed_items.get(named, set()):
                sealed_updates.append(update)
                self.payloads.pop(named, None)
            else:
                refused_updates.append({"delta_id": named, "subject": update["update"]["subject"],
                                        "code": sealing.CONTRACT_FAILED})
        updates = sealed_updates
        envelopes, failed_declarations, left_declarations = self.candidate_checks(envelopes, parameters)
        settlement += self.settle_orphans(sealed_at, parameters, height)
        declarations = [{"type": "publisher_declaration", "body": e} for e in envelopes]
        declarations += [{"type": "registry_update", "body": u} for u in updates]
        sealed = self.sealed | {rules.declaration_hash(e["publisher"]) for e in envelopes}
        if any(not f["reduces"] and f["hash"] not in sealed and f["hash"] not in late
               for found in self.discovered.values() for f in found):
            raise ValueError("a discovered Declaration that does not reduce authority is sealed in the next Epoch")
        if any(f.get("discarded_by") in sealed and f["hash"] not in sealed
               for found in self.discovered.values() for f in found):
            raise ValueError("a discarded pending replacement is sealed at or below the Epoch of its reversal")
        probe = copy.deepcopy(self.log)
        if probe.epoch(self.epoch_input(height, sealed_at, parameters, declarations))["status"] != "accepted":
            raise ValueError("the Epoch's Declarations do not replay")
        for publisher in sorted(self.publishers()):
            self.refresh(publisher, height + 1, self.place_order(publisher, probe.declaration(publisher)),
                         probe.declaration(publisher))
        held = {p: self.reducing_pending(p, sealed) for p in self.publishers()}
        held = {p: hashes for p, hashes in held.items() if hashes}
        deferred_i4, gone, left, replaced = set(), set(), [], {}
        maximum = parameters["max_inclusion_epochs"]
        while True:
            planned, deferred, holding, dropped = self.plan(height, parameters, held, deferred_i4, probe, gone)
            left += dropped
            entries = declarations + [entry for _, entry, _ in planned]
            ordered = sealing.canonical_order(entries)
            trial = copy.deepcopy(self.log)
            result = trial.epoch(self.epoch_input(height, sealed_at, parameters, entries))
            if result["status"] != "accepted":
                raise AssertionError(result)
            failures = []
            for entry, disposition in zip(ordered, result["entries"]):
                if disposition is not None and disposition["disposition"] != "valid":
                    ref = next(ref for ref, e, _ in planned if e is entry)
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
                touched.add(publisher)
                if ref["type"] == "publisher_catalog":
                    state = self.collections[(publisher, name)]
                    turn = (0, place_key(state["place"], publisher))
                    if "C1" in failed:
                        was_base = self.base_mode(publisher, name)
                        state["failed_c1"] = True
                        c1_codes = sorted({code for condition, code in trial.judge_catalog(
                            state["envelope"], sealed_at, parameters) if condition == "C1"})
                        left.append((turn, {**ref, "condition": "C1", "codes": c1_codes, "reported": True}))
                        if was_base:
                            for (p, url), entry in sorted(self.urls.items()):
                                if p != publisher or entry["collection"] != name:
                                    continue
                                item = self.no_longer_record(publisher, name, url)
                                if item is not None:
                                    gone.add((publisher, url))
                                    held_latest = trial.latest[(publisher, name)]
                                    body = items.publisher_item_body(
                                        item, held_latest["envelope"]["catalog"],
                                        self.lists[self.latest_id(publisher, name)]["list"])
                                    judged, _ = trial.judge_item(body, height, parameters)
                                    left.append(((1 + KIND_ORDER.index(items.kind(item)),
                                                  place_key(entry["place"], publisher)),
                                                 {"type": "publisher_item", "publisher": publisher,
                                                  "collection": name, "url": url, "item": items.item_id(item),
                                                  "condition": "I7",
                                                  "codes": sorted({code for _, code in judged}),
                                                  "reported": False}))
                    elif "C4" in failed:
                        state["c4_failed"] = True
                        left.append((turn, {**ref, "condition": "C4", "codes": codes, "reported": False}))
                    else:
                        raise AssertionError((ref, disposition))
                    continue
                entry = self.urls[(publisher, ref["url"])]
                turn = (1 + KIND_ORDER.index(items.kind(entry["item"])), place_key(entry["place"], publisher))
                bare = {k: v for k, v in ref.items() if k != "catalog"}
                if "I7" in failed:
                    replacing = self.waiting_after_catalogs(publisher, ref["url"], height, sealed_at, parameters,
                                                            declarations, planned, probe)
                    if (replacing is not None and items.item_id(replacing[2]) != ref["item"]
                            and (publisher, ref["url"]) not in replaced):
                        replaced[(publisher, ref["url"])] = (replacing[0], replacing[2])
                        entry.update(collection=replacing[0], item=replacing[2])
                        continue
                    gone.add((publisher, ref["url"]))
                    left.append((turn, {**bare, "condition": "I7", "codes": codes, "reported": False}))
                elif "I4" in failed:
                    deferred_i4.add((publisher, name))
                elif failed == ["I5"]:
                    accepted = self.last_accepted(publisher, name)
                    self.admission[accepted][ref["url"]] = {"outcome": "refused", "codes": codes, "at_turn": True}
                    gone.add((publisher, ref["url"]))
                    left.append((turn, {**bare, "condition": "I5", "codes": codes, "reported": True}))
                else:
                    raise AssertionError((ref, disposition))
            for publisher in sorted(touched):
                self.refresh(publisher, height + 1, self.place_order(publisher, probe.declaration(publisher)),
                             probe.declaration(publisher))
            for slot, (name, item) in replaced.items():
                if slot in self.urls:
                    self.urls[slot].update(collection=name, item=item)
        for entry in holding:
            if entry["eligibility"] is not None and entry["eligibility"] + maximum <= height:
                raise ValueError("a Declaration that reduces authority is sealed later than the earliest ceiling "
                                 "among the waiting publications of its Publisher allows")
        epoch = self.epoch_input(height, sealed_at, parameters, entries)
        result = self.log.epoch(epoch)
        if result["status"] != "accepted" or any(
                d is not None and d["disposition"] != "valid" for d in result["entries"]):
            raise AssertionError(result)
        if self.log.state() != trial.state():
            raise AssertionError("the sealed state differs from the planned one")
        self.height = height
        self.sealed = sealed
        for identifier in self.log.withdrawals:
            self.payloads.pop(identifier, None)
        for publisher in sorted(self.publishers()):
            self.refresh(publisher, height + 1, self.place_order(publisher, self.log.declaration(publisher)))
        self.open_windows()
        moved = {(d["publisher"], d["collection"] if d["type"] == "publisher_catalog" else d["url"], d["type"])
                 for d in deferred}
        for (publisher, name), state in self.collections.items():
            if not self.catalog_waits(publisher, name):
                state.update(place=None, eligibility=None)
            elif (publisher, name, "publisher_catalog") in moved:
                state["eligibility"] = height + 1
        for (publisher, url), entry in self.urls.items():
            if not self.window_opened(publisher) and (publisher, url, "publisher_item") in moved:
                entry["eligibility"] = height + 1
        out = {"settlement": settlement, "entries": epoch["entries"],
               "sealed": [{**ref, "eligibility": eligibility, "ceiling": eligibility + maximum}
                          for ref, _, eligibility in planned],
               "left": [entry for _, entry in sorted(left, key=lambda pair: pair[0])], "deferred": deferred,
               "records_removed": result["records_removed"]}
        if holding:
            out["held"] = [{k: v for k, v in h.items() if k != "eligibility"} for h in holding]
        if failed_declarations:
            out["declarations_failed"] = failed_declarations
        if left_declarations:
            out["declarations_left"] = left_declarations
        if refused_updates:
            out["updates_refused"] = refused_updates
        return out

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
                                                      key=lambda kv: (place_key(kv[1]["place"], kv[0][0]),
                                                                      kv[0][1].encode()))]
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
