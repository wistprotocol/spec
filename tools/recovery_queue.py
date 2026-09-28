import catalogs
import collection_rules as rules
import items

REJECTED = "WIST1-E13"
REGRESSED = "WIST2-E05"


def refusal(check, *arguments):
    try:
        check(*arguments)
    except items.Refused as refused:
        return refused.code
    return None


def signing_key(envelope, source):
    catalog, sig = envelope["catalog"], envelope["sig"]
    signature = rules.canonical_b64url(sig["value"], 64)
    instant = catalogs.log_seconds(catalog["generated_at"])
    for entry in rules.binding_candidates(source, catalog["collection"], sig["key_id"]):
        raw = rules.canonical_b64url(entry["x"], 32)
        if (rules.usable_point(raw) and rules.time_eligible(entry, instant)
                and rules.verifies(raw, signature, items.jcs(catalog))):
            return entry["kid"]
    return None


def order_key(entry):
    catalog = entry["envelope"]["catalog"]
    return catalogs.log_seconds(catalog["generated_at"]), catalogs.catalog_id(catalog).encode()


class Queue:
    def __init__(self, before, owner, end):
        self.before = before
        self.owner = owner
        self.end = end
        self.held = {}
        self.first = {}
        self.frozen = {}

    def sources(self):
        return [self.before, self.owner]

    def order(self, envelope, key, floor):
        catalog = envelope["catalog"]
        queued = self.held.get((catalog["collection"], key))
        if queued is not None and queued["catalog"] == catalogs.catalog_id(catalog):
            return "idempotent"
        instant = catalogs.log_seconds(catalog["generated_at"])
        if floor is not None and instant <= floor:
            return REGRESSED
        if queued is not None and instant <= order_key(queued)[0]:
            return REGRESSED
        return "accepted"

    def enqueue(self, name, key, entry):
        self.held[(name, key)] = {**entry, "key": key}
        self.first.setdefault(name, entry["place"])

    def names(self):
        return sorted({name for name, _ in self.held}, key=str.encode)

    def settle(self, source, clock, parameters):
        results, survivors = [], {}
        for (name, key), entry in sorted(self.held.items(), key=lambda kv: (kv[1]["place"], kv[0][1])):
            code = refusal(catalogs.judge_catalog, entry["envelope"], source, clock, parameters)
            results.append({"collection": name, "key": key, "catalog": entry["catalog"],
                            "outcome": REJECTED if code is not None else "survivor",
                            **({"condition_code": code} if code is not None else {})})
            if code is None and (name not in survivors or order_key(entry) > order_key(survivors[name])):
                survivors[name] = entry
        for result in results:
            if result["outcome"] == "survivor" and survivors[result["collection"]]["catalog"] != result["catalog"]:
                result["outcome"] = "not_latest"
        return results, survivors
