import hashlib

import items
import tree_files

CHANGE_LIST_CAP_BYTES = 1048576
CHANGE_CHAIN_MAX = 16
MEMBERS = frozenset(("previous", "catalog", "dropped", "items"))
REPLACED_FILE_SECONDS = 86400
DISCARDED = "WIST2-E08"


class FormError(Exception):
    pass


def name_of(catalog_id):
    return catalog_id[len("sha256:"):]


def key_of(element):
    return items.item_key(element["url"])


def _ascending(keys):
    return all(a < b for a, b in zip(keys, keys[1:]))


def parse(octets, name=None):
    try:
        obj = items.strict_loads(bytes(octets))
    except items.NotJcsInput as error:
        raise FormError(f"not valid JCS input: {error}")
    if not isinstance(obj, dict) or set(obj) != MEMBERS:
        raise FormError("not an object of exactly previous, catalog, dropped and items")
    for member in ("previous", "catalog"):
        if not isinstance(obj[member], str) or not items.HASH_PATTERN.fullmatch(obj[member]):
            raise FormError(f"{member} is not a Catalog ID")
    dropped = obj["dropped"]
    if not isinstance(dropped, list) or not all(
            isinstance(k, str) and items.HEX64_PATTERN.fullmatch(k) for k in dropped):
        raise FormError("dropped is not an array of keys")
    dropped_keys = [bytes.fromhex(k) for k in dropped]
    if not _ascending(dropped_keys):
        raise FormError("dropped is not in strictly ascending order")
    elements = obj["items"]
    if not isinstance(elements, list) or not all(
            isinstance(e, dict) and isinstance(e.get("url"), str) for e in elements):
        raise FormError("items is not an array of objects with a string url")
    item_keys = [key_of(e) for e in elements]
    if not _ascending(item_keys):
        raise FormError("items is not in strictly ascending order of key")
    if set(dropped_keys) & set(item_keys):
        raise FormError("a key both dropped and listed")
    try:
        canonical = items.jcs(obj)
    except Exception:
        raise FormError("no JCS serialization")
    if canonical != bytes(octets):
        raise FormError("not the JCS serialization of its object")
    if name is not None and obj["catalog"] != "sha256:" + name:
        raise FormError("catalog is not the Catalog ID that names the file")
    return obj


def form_disposition(octets, name=None):
    try:
        parse(octets, name)
    except FormError:
        return "form"
    return "accepted"


def apply(listed, change):
    by_key = {key_of(item): item for item in listed}
    for key in change["dropped"]:
        by_key.pop(bytes.fromhex(key), None)
    for element in change["items"]:
        by_key[key_of(element)] = element
    return [by_key[key] for key in sorted(by_key)]


def difference(served, new):
    served_by_key = {key_of(item): item for item in served}
    new_by_key = {key_of(item): item for item in new}
    changed = [new_by_key[k] for k in sorted(new_by_key)
               if k not in served_by_key or items.item_id(served_by_key[k]) != items.item_id(new_by_key[k])]
    dropped = [k.hex() for k in sorted(served_by_key) if k not in new_by_key]
    return dropped, changed


def write(served_catalog_id, served_list, new_catalog_id, new_list):
    if served_catalog_id is None or served_catalog_id == new_catalog_id:
        return None
    dropped, changed = difference(served_list, new_list)
    octets = items.jcs({"previous": served_catalog_id, "catalog": new_catalog_id, "dropped": dropped, "items": changed})
    if len(octets) > CHANGE_LIST_CAP_BYTES:
        return None
    return octets


def serve_timeline(steps, stops, clocks, declaration_stops_at=None):
    written, previous, interval = {}, {}, {}
    history = []
    served = None

    def stopped_at(instant):
        return {name for name, at in stops if at <= instant}

    def chain_of(name, stopped):
        chain = []
        while name in written and name not in stopped:
            chain.append(name)
            name = previous[name]
        return chain

    for step in steps:
        catalog_id, listed, served_at = step["id"], step["list"], step["served_at"]
        octets = None if served is None else write(served[0], served[1], catalog_id, listed)
        if octets is not None:
            written[name_of(catalog_id)] = octets
            previous[name_of(catalog_id)] = name_of(served[0])
        stopped = stopped_at(served_at)
        full = chain_of(name_of(catalog_id), stopped)
        if history:
            for name in chain_of(history[-1]["name"], stopped)[:CHANGE_CHAIN_MAX]:
                if name in full[CHANGE_CHAIN_MAX:]:
                    interval[name] = (served_at, served_at + REPLACED_FILE_SECONDS)
        history.append({"name": name_of(catalog_id), "served_at": served_at, "written": set(written)})
        served = (catalog_id, listed)

    def obliged(clock):
        current = [h for h in history if h["served_at"] <= clock]
        if not current:
            return set(), set()
        must = set(chain_of(current[-1]["name"], stopped_at(clock))[:CHANGE_CHAIN_MAX])
        must |= {name for name, (start, end) in interval.items() if start <= clock < end}
        return must, current[-1]["written"]

    out = []
    for clock in clocks:
        if declaration_stops_at is not None and clock >= declaration_stops_at:
            kept, known = obliged(declaration_stops_at)
            must = kept if clock < declaration_stops_at + REPLACED_FILE_SECONDS else set()
        else:
            must, known = obliged(clock)
        stopped = stopped_at(clock) & known
        must = must - stopped
        out.append({"must_serve": sorted(must), "may_serve": sorted(known - must - stopped),
                    "must_not_serve": sorted(stopped)})
    return out, written


class Suspended(Exception):
    pass


class Site:
    def __init__(self, held, served, cap, budget=None, objects=None):
        self.held = held
        self.served = served
        self.cap = cap
        self.budget = budget
        self.objects = objects
        self.fetched = []
        self.whole = {}
        self.octets = 0

    def get(self, digest):
        if digest in self.held:
            return self.held[digest]
        if self.objects is not None:
            if self.objects == 0:
                raise Suspended()
            self.objects -= 1
        if digest not in self.fetched:
            self.fetched.append(digest)
        octets = self.served.get(digest)
        if octets is None:
            return None
        allowance = None if self.budget is None else self.budget - self.octets
        if allowance is not None and allowance <= self.cap and len(octets) > allowance:
            self.octets = self.budget
            raise Suspended()
        if len(octets) > self.cap:
            return octets
        self.octets += len(octets)
        if hashlib.sha256(octets).hexdigest() == digest:
            self.whole[digest] = octets
        return octets


def walk(catalog, held_tree_files, served_tree_files, budget=None, parameters=None, objects=None):
    parameters = {**tree_files.DEFAULT_PARAMETERS, **(parameters or {})}
    site = Site(held_tree_files, served_tree_files, parameters["tree_file_cap_bytes"], budget, objects)
    out, listed = {}, None
    try:
        listed = tree_files.walk(catalog, site, parameters)
        out["list"] = [items.item_id(i) for i in listed]
    except Suspended:
        out["suspended"] = True
    except tree_files.TreeRefusal:
        out["refused"] = tree_files.TreeRefusal.code
    out.update(tree_files_fetched=sorted(site.fetched), octets=site.octets)
    return out, site.whole, listed


def _discard(condition, catalog_id, at, read, octets):
    return {"chain": "discarded", "lists_read": read, "octets": octets,
            "report": {"code": DISCARDED, "condition": condition, "catalog": catalog_id, "change_list": at}}


def read_chain(catalog, held, change_lists, budget=None, objects=None):
    catalog_id = items.catalog_id(catalog)
    for listed in held.values():
        if len(listed) == catalog["size"] and items.root_string(listed) == catalog["root"]:
            return {"chain": "held", "lists_read": [], "octets": 0,
                    "list": [items.item_id(i) for i in listed]}, listed
    if not held:
        return {"chain": "none", "lists_read": [], "octets": 0}, None
    remaining = budget
    read, parsed, octets = [], [], 0
    at = catalog_id
    while True:
        if objects is not None and len(read) == objects:
            return {"chain": "suspended", "lists_read": read, "octets": octets}, None
        answer = change_lists.get(name_of(at))
        if answer is None:
            return _discard("fetch", catalog_id, at, read, octets), None
        if remaining is not None and remaining <= CHANGE_LIST_CAP_BYTES and len(answer) > remaining:
            return {"chain": "suspended", "lists_read": read, "octets": octets + remaining}, None
        if len(answer) > CHANGE_LIST_CAP_BYTES:
            return _discard("size", catalog_id, at, read, octets), None
        if remaining is not None:
            remaining -= len(answer)
        octets += len(answer)
        read.append(at)
        try:
            change = parse(answer, name_of(at))
        except FormError:
            return _discard("form", catalog_id, at, read, octets), None
        parsed.append(change)
        if change["previous"] in held:
            break
        if len(parsed) == CHANGE_CHAIN_MAX:
            return _discard("chain", catalog_id, at, read, octets), None
        at = change["previous"]
    listed = held[parsed[-1]["previous"]]
    for change in reversed(parsed):
        listed = apply(listed, change)
    if len(listed) != catalog["size"] or items.root_string(listed) != catalog["root"]:
        return _discard("result", catalog_id, catalog_id, read, octets), None
    return {"chain": "accepted", "previous": parsed[-1]["previous"], "lists_read": read, "octets": octets,
            "list": [items.item_id(i) for i in listed]}, listed


def _obtain(catalog, held, change_lists, held_tree_files, served_tree_files, budget, parameters, after_suspension,
            objects=None):
    if after_suspension:
        out, listed = read_chain(catalog, held, {}, budget)
        if out["chain"] != "held":
            out, listed = {"chain": "after_suspension", "lists_read": [], "octets": 0}, None
    else:
        out, listed = read_chain(catalog, held, change_lists, budget, objects)
    whole = {}
    if out["chain"] in ("discarded", "none", "after_suspension"):
        remaining = None if budget is None else budget - out["octets"]
        left = None if objects is None else objects - len(out["lists_read"])
        out["walk"], whole, listed = walk(catalog, held_tree_files, served_tree_files, remaining, parameters, left)
    return out, whole, listed


def obtain(catalog, held, change_lists, held_tree_files, served_tree_files, budget=None, parameters=None,
           objects=None):
    return _obtain(catalog, held, change_lists, held_tree_files, served_tree_files, budget, parameters, False,
                   objects)[0]


class Aggregator:
    def __init__(self, held=None, tree_files_held=None):
        self.held = dict(held or {})
        self.tree = dict(tree_files_held or {})
        self.after_suspension = False

    def pull(self, catalog, change_lists, served_tree_files, budget=None, parameters=None, objects=None):
        out, whole, listed = _obtain(catalog, self.held, change_lists, self.tree, served_tree_files, budget,
                                     parameters, self.after_suspension, objects)
        self.tree.update(whole)
        if listed is not None:
            self.held[items.catalog_id(catalog)] = listed
            self.after_suspension = False
        elif out["chain"] == "suspended":
            self.after_suspension = True
        return out
