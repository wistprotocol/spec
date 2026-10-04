import calendar
import copy
import datetime
import re

import rfc8785

import collection_rules as rules

LOG_TIMESTAMP_MAX_S = 253402300799
DAY_S = 86400
LOG_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class HistoryRejected(Exception):
    def __init__(self, code, reason):
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


def log_seconds(value):
    if not LOG_TIMESTAMP.fullmatch(value):
        raise ValueError(f"not a whole-second Log timestamp: {value}")
    return calendar.timegm(datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").timetuple())


def log_timestamp(seconds):
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def public_raw(entry):
    return rules.canonical_b64url(entry["x"], 32)


def validated(envelope, parameters, read_parameters=True):
    try:
        rules.validate_declaration(envelope, parameters, read_parameters)
    except rules.RuleViolation as violation:
        raise HistoryRejected(violation.code, violation.reason) from None
    return envelope["publisher"]


def authenticate(predecessor, envelope):
    incoming = envelope["publisher"]
    sig = envelope["sig"]
    pool = list(incoming["keys"])
    if predecessor is not None:
        pool = predecessor["keys"] + predecessor.get("recovery_keys", []) + pool
    named = {public_raw(e) for e in pool if e["kid"] == sig["key_id"]}
    usable = [raw for raw in named if rules.usable_point(raw)]
    if not usable:
        raise HistoryRejected("WIST1-E02", "no usable candidate for the Declaration signer")
    signature = rules.canonical_b64url(sig["value"], 64)
    message = rfc8785.dumps(incoming)
    verified = [raw for raw in usable if rules.verifies(raw, signature, message)]
    if not verified:
        raise HistoryRejected("WIST1-E01", "no candidate verifies the Declaration signature")
    signer = verified[0]
    if predecessor is None:
        return "initial", signer
    if signer in {public_raw(e) for e in predecessor["keys"]}:
        return "ordinary_rotation", signer
    if signer in {public_raw(e) for e in predecessor.get("recovery_keys", [])}:
        return "recovery_rotation", signer
    return "fresh_identity", signer


def check_continuity(predecessor, incoming, classification, signer):
    protected = predecessor.get("recovery_keys", [])
    if protected and signer not in {public_raw(e) for e in protected}:
        if rfc8785.dumps(incoming.get("recovery_keys")) != rfc8785.dumps(protected):
            raise HistoryRejected("WIST1-E08", "recovery_keys changed without a recovery-key signature")
    if classification == "ordinary_rotation" and "next_keys" in predecessor:
        kept = (sorted(e["kid"] for e in incoming["keys"]) == sorted(e["kid"] for e in predecessor["keys"])
                and incoming.get("next_keys") == predecessor["next_keys"])
        installed = rules.key_set_fingerprint(incoming["keys"]) == predecessor["next_keys"]
        if not (kept or installed):
            raise HistoryRejected("WIST1-E08", "ordinary rotation outside the next_keys commitment")


def evaluate_replacement(predecessor_envelope, envelope, parameters=None):
    try:
        predecessor = validated(predecessor_envelope, parameters, read_parameters=False)
        incoming = validated(envelope, parameters, read_parameters=False)
        if rfc8785.dumps(incoming) == rfc8785.dumps(predecessor):
            return "idempotent"
        validated(envelope, parameters)
        if incoming["seq"] <= predecessor["seq"]:
            raise HistoryRejected("WIST1-E08", "seq not above the accepted floor")
        if incoming.get("prev_declaration") != rules.declaration_hash(predecessor):
            raise HistoryRejected("WIST1-E08", "prev_declaration does not name the predecessor")
        classification, signer = authenticate(predecessor, envelope)
        check_continuity(predecessor, incoming, classification, signer)
    except HistoryRejected as rejection:
        return rejection.code
    return classification


def record_stays(publisher, record):
    if "collections" not in publisher:
        return record["collection"] == rules.IMPLICIT_DEFAULT
    collection = rules.collection_named(publisher, record["collection"])
    return collection is not None and rules.scope_covers(publisher, collection, record["url"])


def ordered(records):
    return sorted(records, key=lambda r: (r["url"].encode(), r["collection"].encode()))


class Replay:
    def __init__(self, recovery_window_days, declaration_activation_epochs, parameters):
        self.recovery_window_days = recovery_window_days
        self.declaration_activation_epochs = declaration_activation_epochs
        self.parameters = parameters
        self.current = None
        self.floor = None
        self.window = None
        self.pending = None
        self.live = {}

    def narrow(self, kind, publisher, height, transitions):
        removed = [dict(url=url, collection=collection, sealed_height=sealed)
                   for url, (collection, sealed) in self.live.items()
                   if sealed < height and not record_stays(publisher, {"url": url, "collection": collection})]
        for record in removed:
            del self.live[record["url"]]
        transitions.append({"kind": kind, "declaration": rules.declaration_hash(publisher),
                            "narrows": True, "removed": ordered(removed)})

    def still(self, kind, publisher, transitions):
        transitions.append({"kind": kind, "declaration": rules.declaration_hash(publisher),
                            "narrows": False, "removed": []})

    def open_window(self, before, publisher, sealed_at):
        end = sealed_at + self.recovery_window_days * DAY_S
        if end > LOG_TIMESTAMP_MAX_S:
            raise HistoryRejected("WIST1-E08", "recovery window end beyond the last Log timestamp")
        self.window = {"end": end, "chain_head": publisher, "before": before, "owner": publisher}

    def activate(self, height, transitions):
        head = self.pending["head"]
        self.current = head
        self.pending = None
        self.narrow("activation", head, height, transitions)

    def served_again(self, publisher):
        digest = rules.declaration_hash(publisher)
        heads = [self.current] + ([self.pending["head"]] if self.pending else [])
        return any(head is not None and digest == rules.declaration_hash(head) for head in heads)

    def chain_head_served_again(self, publisher):
        return (self.window is not None and not self.served_again(publisher)
                and rules.declaration_hash(publisher) == rules.declaration_hash(self.window["chain_head"]))

    def sources(self):
        if self.window:
            return [self.window["before"], self.window["owner"]]
        return [self.current] if self.current is not None else []

    def fetch(self, envelope, height, sealed_at, transitions, sealing=True):
        incoming = validated(envelope, self.parameters, read_parameters=False)
        if self.chain_head_served_again(incoming):
            self.still("recovery_chain_head", incoming, transitions)
            return
        self.apply(envelope, height, sealed_at, transitions, sealing=sealing)

    def apply(self, envelope, height, sealed_at, transitions, read_parameters=True, sealing=True):
        incoming = validated(envelope, self.parameters, read_parameters=False)
        if self.current is not None and self.served_again(incoming):
            self.still("idempotent", incoming, transitions)
            return
        validated(envelope, self.parameters, read_parameters)
        if self.current is None:
            if incoming["seq"] != 0 or "prev_declaration" in incoming:
                raise HistoryRejected("WIST1-E08", "the first Declaration of a history is not seq 0")
            authenticate(None, envelope)
            self.current, self.floor = incoming, 0
            self.still("initial", incoming, transitions)
            return
        if incoming["seq"] <= self.floor:
            raise HistoryRejected("WIST1-E08", "seq not above the accepted floor")
        eligible = {rules.declaration_hash(self.current): self.current}
        if self.window:
            eligible[rules.declaration_hash(self.window["chain_head"])] = self.window["chain_head"]
        if self.pending:
            eligible[rules.declaration_hash(self.pending["head"])] = self.pending["head"]
        predecessor = eligible.get(incoming.get("prev_declaration"))
        if predecessor is None:
            raise HistoryRejected("WIST1-E08", "prev_declaration names no eligible predecessor")
        classification, signer = authenticate(predecessor, envelope)
        check_continuity(predecessor, incoming, classification, signer)
        self.floor = incoming["seq"]
        if self.pending:
            if predecessor is self.pending["head"]:
                self.pending["head"] = incoming
                self.still("pending_replacement", incoming, transitions)
                return
            if classification == "fresh_identity":
                raise HistoryRejected("WIST1-E08", "fresh identity naming the current Declaration beside a pending head")
            self.current, self.pending = incoming, None
            if classification == "ordinary_rotation":
                self.narrow("reversal_ordinary_rotation", incoming, height, transitions)
            else:
                self.open_window(predecessor, incoming, sealed_at)
                self.still("reversal_recovery_rotation", incoming, transitions)
            return
        if self.window:
            self.current = incoming
            if predecessor is self.window["chain_head"] and classification != "fresh_identity":
                self.window["chain_head"] = incoming
                self.still("in_window_chain", incoming, transitions)
            else:
                self.still("in_window_competitor", incoming, transitions)
            return
        if classification == "ordinary_rotation":
            self.current = incoming
            self.narrow("ordinary_rotation", incoming, height, transitions)
        elif classification == "recovery_rotation":
            self.current = incoming
            self.open_window(predecessor, incoming, sealed_at)
            self.still("recovery_rotation", incoming, transitions)
        else:
            self.pending = {"head": incoming, "activation_height": height + self.declaration_activation_epochs}
            self.still("fresh_identity_pending", incoming, transitions)
            if sealing and self.pending["activation_height"] == height:
                self.activate(height, transitions)

    def apply_group(self, envelopes, height, sealed_at, transitions):
        reference = {rules.declaration_hash(self.current)} if self.current else set()
        if self.pending:
            reference.add(rules.declaration_hash(self.pending["head"]))
        if all(rules.declaration_hash(e["publisher"]) in reference for e in envelopes):
            for envelope in envelopes:
                self.apply(envelope, height, sealed_at, transitions)
            return
        if len({rfc8785.dumps(e) for e in envelopes}) != 1:
            raise HistoryRejected("WIST1-E08", "distinct Declarations of one seq in one Epoch")
        self.apply(envelopes[0], height, sealed_at, transitions)

    def epoch(self, epoch):
        height, sealed_at = epoch["height"], log_seconds(epoch["sealed_at"])
        transitions = []
        if self.window and sealed_at >= self.window["end"]:
            head = self.window["chain_head"]
            self.current, self.window = head, None
            self.narrow("settlement", head, height, transitions)
        if self.pending and self.pending["activation_height"] <= height:
            self.activate(height, transitions)
        by_seq = {}
        for envelope in epoch["declarations"]:
            by_seq.setdefault(envelope["publisher"]["seq"], []).append(envelope)
        for seq in sorted(by_seq):
            self.apply_group(by_seq[seq], height, sealed_at, transitions)
        if epoch["records"] and (self.window or self.current is None):
            raise ValueError("records cannot seal inside an open recovery window or before any Declaration")
        sealed, rejected = [], []
        for record in epoch["records"]:
            if rules.record_in_scope(self.current, record["collection"], record["url"]):
                self.live[record["url"]] = (record["collection"], height)
                sealed.append(dict(record))
            else:
                rejected.append(dict(record, code="WIST1-E03"))
        return {"height": height,
                "current_declaration": rules.declaration_hash(self.current) if self.current else None,
                "pending_head": rules.declaration_hash(self.pending["head"]) if self.pending else None,
                "activation_height": self.pending["activation_height"] if self.pending else None,
                "window_end": log_timestamp(self.window["end"]) if self.window else None,
                "transitions": transitions,
                "records_sealed": ordered(sealed),
                "records_rejected": ordered(rejected)}


def replay(epochs, recovery_window_days=7, declaration_activation_epochs=24, parameters=None):
    state = Replay(recovery_window_days, declaration_activation_epochs, parameters)
    results, previous = [], None
    for epoch in epochs:
        if previous is not None and (epoch["height"] != previous["height"] + 1
                                     or log_seconds(epoch["sealed_at"]) <= log_seconds(previous["sealed_at"])):
            raise ValueError("Epochs must have consecutive heights and increasing sealed_at")
        results.append(state.epoch(epoch))
        previous = epoch
    live = [dict(url=url, collection=collection, sealed_height=height)
            for url, (collection, height) in state.live.items()]
    return {"epochs": results, "live_records": ordered(live)}


def pull_sources(known_envelope, fetch_outcome, fetched_envelope, parameters=None):
    if not rules.pull_proceeds(fetch_outcome):
        return "not_fetched", []
    if fetch_outcome == "not_modified":
        return "idempotent", [known_envelope["publisher"]]
    acceptance = evaluate_replacement(known_envelope, fetched_envelope, parameters)
    if acceptance in ("idempotent", "fresh_identity"):
        return acceptance, [known_envelope["publisher"]]
    if acceptance == "ordinary_rotation":
        return acceptance, [fetched_envelope["publisher"]]
    if acceptance == "recovery_rotation":
        return acceptance, [known_envelope["publisher"], fetched_envelope["publisher"]]
    return acceptance, []


def collection_names(sources):
    names = []
    for publisher in sources:
        for collection in rules.collections_of(publisher):
            if collection["name"] not in names:
                names.append(collection["name"])
    return names


def collections_pulled(known_envelope, fetch_outcome, fetched_envelope, parameters=None):
    acceptance, sources = pull_sources(known_envelope, fetch_outcome, fetched_envelope, parameters)
    return acceptance, collection_names(sources)


def stopped_pull(state, acceptance):
    first_contact = state.current is None
    return {"acceptance": acceptance, "proceeds": False, "sources": [], "collections_pulled": [],
            "disposition": "WIST2-E04" if first_contact else "WIST2-E01", "noise": first_contact}


def pull(replay, fetch_outcome, fetched_envelope, height, sealed_at, discovered=()):
    state = copy.deepcopy(replay)
    for envelope in discovered:
        try:
            state.apply(envelope, height, sealed_at, [], read_parameters=False, sealing=False)
        except HistoryRejected:
            continue
    if not rules.pull_proceeds(fetch_outcome):
        return stopped_pull(state, "not_fetched")
    admission = copy.deepcopy(state)
    transitions = []
    try:
        state.fetch(fetched_envelope, height, sealed_at, transitions, sealing=False)
    except HistoryRejected as rejection:
        return stopped_pull(admission, rejection.code)
    sources = state.sources()
    return {"acceptance": transitions[0]["kind"], "proceeds": True, "sources": sources,
            "collections_pulled": collection_names(sources), "disposition": None, "noise": False}
