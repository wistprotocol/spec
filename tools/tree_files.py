import hashlib
import re

import items

DEFAULT_PARAMETERS = {"tree_file_cap_bytes": 65536, "tree_depth_max": 16}
BUCKET_CAPACITY = 16
HEX_DIGITS = "0123456789abcdef"
ENTRY_MEMBERS = frozenset(("prefix", "count", "file"))
CHILDREN_MAX = 16
DIGIT = re.compile(r"[0-9a-f]")


class TreeRefusal(Exception):
    code = "WIST2-E07"


def key_hex(item):
    return items.item_key(item["url"]).hex()


def plan(ordered, capacity=BUCKET_CAPACITY, depth_max=DEFAULT_PARAMETERS["tree_depth_max"], prefix="", level=1):
    if len(ordered) <= capacity or level == depth_max:
        return {"items": list(ordered)}
    groups = {}
    for item in ordered:
        groups.setdefault(key_hex(item)[len(prefix)], []).append(item)
    return {"children": [{"prefix": prefix + digit, "count": len(groups[digit]),
                          "node": plan(groups[digit], capacity, depth_max, prefix + digit, level + 1)}
                         for digit in HEX_DIGITS if digit in groups]}


def emit(node, files):
    if "items" in node:
        obj = {"items": node["items"]}
    else:
        obj = {"children": [{"prefix": e["prefix"], "count": e["count"], "file": "sha256:" + emit(e["node"], files)}
                            for e in node["children"]]}
    octets = items.jcs(obj)
    digest = hashlib.sha256(octets).hexdigest()
    files[digest] = octets
    return digest


def write_tree(listed, capacity=BUCKET_CAPACITY, depth_max=DEFAULT_PARAMETERS["tree_depth_max"]):
    files = {}
    tree = emit(plan(items.in_list_order(listed), capacity, depth_max), files)
    return "sha256:" + tree, files


def fetch(files, digest, cap):
    octets = files.get(digest)
    if octets is None:
        raise TreeRefusal("tree file unavailable")
    if len(octets) > cap:
        raise TreeRefusal("tree file above tree_file_cap_bytes")
    if hashlib.sha256(octets).hexdigest() != digest:
        raise TreeRefusal("tree file with another SHA-256")
    try:
        obj = items.strict_loads(octets)
    except items.NotJcsInput:
        raise TreeRefusal("tree file that is not JSON")
    if not isinstance(obj, dict) or len(obj) != 1:
        raise TreeRefusal("tree file that is not an object of one member")
    try:
        canonical = items.jcs(obj)
    except Exception:
        raise TreeRefusal("tree file that has no JCS serialization")
    if canonical != octets:
        raise TreeRefusal("tree file that is not the JCS serialization of its object")
    return obj


def read_bucket(elements, prefix, count):
    if not isinstance(elements, list):
        raise TreeRefusal("items is not an array")
    previous = None
    for element in elements:
        if not isinstance(element, dict) or not isinstance(element.get("url"), str):
            raise TreeRefusal("a bucket element without a string url")
        key = items.item_key(element["url"])
        if previous is not None and key <= previous:
            raise TreeRefusal("bucket keys not in strictly ascending order")
        if not key.hex().startswith(prefix):
            raise TreeRefusal("an Item key outside the bucket's prefix")
        previous = key
    if len(elements) != count:
        raise TreeRefusal("a bucket listing another number of Items than its count")
    return elements


def read_children(children, prefix, count):
    if not isinstance(children, list) or not 1 <= len(children) <= CHILDREN_MAX:
        raise TreeRefusal("children is not an array of 1 to 16 entries")
    previous = None
    for entry in children:
        if not isinstance(entry, dict) or set(entry) != ENTRY_MEMBERS:
            raise TreeRefusal("an entry without exactly prefix, count and file")
        p = entry["prefix"]
        if not (isinstance(p, str) and len(p) == len(prefix) + 1 and p.startswith(prefix)
                and DIGIT.fullmatch(p[-1])):
            raise TreeRefusal("a prefix that is not the file's prefix followed by one digit")
        if previous is not None and p <= previous:
            raise TreeRefusal("prefixes not in strictly ascending order")
        previous = p
        if isinstance(entry["count"], bool) or not isinstance(entry["count"], int) or entry["count"] < 1:
            raise TreeRefusal("a count that is not an integer of at least 1")
        if not isinstance(entry["file"], str) or not items.HASH_PATTERN.fullmatch(entry["file"]):
            raise TreeRefusal("a file that is not a SHA-256 name")
    if sum(entry["count"] for entry in children) != count:
        raise TreeRefusal("counts that do not add up to the count naming the file")
    return children


def walk_file(files, digest, prefix, level, count, parameters, out):
    obj = fetch(files, digest, parameters["tree_file_cap_bytes"])
    if "items" in obj:
        out.extend(read_bucket(obj["items"], prefix, count))
        return
    if "children" not in obj:
        raise TreeRefusal("a tree file of no known kind")
    if level >= parameters["tree_depth_max"]:
        raise TreeRefusal("an inner file at level tree_depth_max")
    for entry in read_children(obj["children"], prefix, count):
        walk_file(files, entry["file"][len("sha256:"):], entry["prefix"], level + 1, entry["count"],
                  parameters, out)


def walk(catalog, files, parameters=None):
    parameters = {**DEFAULT_PARAMETERS, **(parameters or {})}
    listed = []
    walk_file(files, catalog["tree"][len("sha256:"):], "", 1, catalog["size"], parameters, listed)
    if len(listed) != catalog["size"]:
        raise TreeRefusal("a list of another number of Items than size")
    if items.root_string(listed) != catalog["root"]:
        raise TreeRefusal("a list whose root is not the Catalog's root")
    return listed


def walk_disposition(catalog, files, parameters=None):
    try:
        listed = walk(catalog, files, parameters)
    except TreeRefusal:
        return {"refused": TreeRefusal.code}
    return {"list": [items.item_id(item) for item in listed]}
