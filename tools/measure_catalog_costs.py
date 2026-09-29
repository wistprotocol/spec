#!/usr/bin/env python3
import argparse
import hashlib
import json
import random
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import catalogs
import collection_rules as rules
import items
import merkle
import tree_files

PUBLISHER = "example.com"
COLLECTION = "default"
WIST_VERSION = "1.0.0"
LANG = "en"
PAYLOAD_OCTETS = 1700
SALT_OCTETS = 16
SECTIONS = ["blog", "docs", "products", "news"]
WORDS = ["alpha", "river", "stone", "orchard", "lantern", "harbor", "meadow", "cinder"]
FIRST_CLOCK = "2026-09-27T13:00:00Z"
SECOND_CLOCK = "2026-09-27T14:00:00Z"
PROBE_MAX = 2000
DEFAULT_ROUNDS = ["100,10,1,1", "10000,1,0,0", "10000,10,1,1", "10000,1000,10,10", "100000,10,1,1",
                  "100000,10000,100,100", "1000000,10,1,1", "1000000,1000,10,10"]

SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"catalog cost measurement").digest())
KEY_ID = rules.thumbprint(rules.b64u(SIGNING_KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)))


def jcs_octets(value):
    return len(items.jcs(value))


def content(url, version):
    text = f"content of {url} v{version} "
    shell = {"extract": "", "links": {"total": 0, "urls": []}, "summary": {"title": f"Title of {url}"}}
    fill = PAYLOAD_OCTETS - jcs_octets(shell)
    shell["extract"] = (text * (fill // len(text) + 1))[:fill]
    return shell


def page_item(url, version, rnd):
    salt = rules.b64u(rnd.randbytes(SALT_OCTETS))
    modified = "2026-09-27T12:%02d:%02dZ" % (version % 60, rnd.randrange(60))
    publication = {"url": url, "modified": modified, "lang": LANG, "content": content(url, version)}
    item, payload = items.new_page_item(PUBLISHER, publication, salt, WIST_VERSION)
    assert item["payload"]["bytes"] == PAYLOAD_OCTETS
    assert items.payload_disposition(item, payload) == "accepted"
    return item


def removed_item(url, generated_at):
    item = {"publisher": PUBLISHER, "url": url, "observed_at": generated_at, "removed": True}
    items.check_item_form(item)
    return item


def collection(n, rnd, avoid=()):
    urls = {}
    while len(urls) < n:
        url = "https://example.com/%s/%s-%s" % (rnd.choice(SECTIONS), "-".join(rnd.choice(WORDS) for _ in range(3)),
                                                 rnd.randrange(10**9))
        if url not in urls and url not in avoid:
            urls[url] = None
    return {url: page_item(url, 0, rnd) for url in urls}


class Catalog:
    def __init__(self, listed, clock, served_at=None):
        self.ordered = items.in_list_order(listed)
        tree, self.files = tree_files.write_tree(self.ordered)
        generated_at = catalogs.next_generated_at(clock, served_at, catalogs.DEFAULT_PARAMETERS["clock_skew_seconds"])
        self.inner = {"wist_version": WIST_VERSION, "publisher": PUBLISHER, "collection": COLLECTION,
                      "generated_at": generated_at, "size": len(self.ordered),
                      "root": items.root_string(self.ordered), "tree": tree}
        self.envelope = {"catalog": self.inner, "sig": {"key_id": KEY_ID, "alg": "Ed25519",
                                                        "value": rules.b64u(SIGNING_KEY.sign(items.jcs(self.inner)))}}
        catalogs.check_envelope_form(self.envelope)
        self.id = catalogs.catalog_id(self.inner)
        self.leaves = [items.leaf(item) for item in self.ordered]
        assert "sha256:" + merkle.merkle_root(self.leaves).hex() == self.inner["root"]
        self.index = {item["url"]: i for i, item in enumerate(self.ordered)}

    def entry(self):
        return {"type": "publisher_catalog", "body": self.envelope}

    def item_body(self, url):
        index = self.index[url]
        body = {"item": self.ordered[index], "collection": self.inner["collection"], "catalog": self.id,
                "proof": {"index": index, "tree_size": len(self.leaves),
                          "path": [h.hex() for h in merkle.audit_path(index, self.leaves)]}}
        assert items.body_disposition(body, self.inner) == "accepted"
        return body

    def item_entry(self, url):
        return {"type": "publisher_item", "body": self.item_body(url)}

    def assert_reference_body(self, url):
        item = self.ordered[self.index[url]]
        assert self.item_body(url) == items.publisher_item_body(item, self.inner, self.ordered)


def pull(catalog, held):
    fetched = {}

    def visit(digest):
        octets = catalog.files[digest]
        if digest not in held:
            fetched[digest] = len(octets)
        for child in items.strict_loads(octets).get("children", ()):
            visit(child["file"][len("sha256:"):])

    visit(catalog.inner["tree"][len("sha256:"):])
    assert tree_files.walk(catalog.inner, {**held, **catalog.files}) == catalog.ordered
    return len(fetched) + 1, sum(fetched.values()) + jcs_octets(catalog.envelope)


def spread(sizes):
    if not sizes:
        return None
    return {"mean": round(sum(sizes) / len(sizes), 1), "min": min(sizes), "max": max(sizes)}


def measure(n, changes, removals, additions, seed, timings):
    rnd = random.Random(seed)
    out = {"N": n, "changed": changes, "removed": removals, "added": additions,
           "bucket_capacity": tree_files.BUCKET_CAPACITY,
           "tree_depth_max": tree_files.DEFAULT_PARAMETERS["tree_depth_max"]}
    clock = {}

    started = time.perf_counter()
    listed = collection(n, rnd)
    first = Catalog(list(listed.values()), FIRST_CLOCK)
    clock["build_collection_s"] = time.perf_counter() - started
    out["url_octets_mean"] = round(sum(len(url) for url in listed) / n, 1)

    if n <= PROBE_MAX:
        first.assert_reference_body(first.ordered[rnd.randrange(n)]["url"])

    urls = list(listed)
    rnd.shuffle(urls)
    changed, removed = urls[:changes], urls[changes:changes + removals]
    after = dict(listed)
    for url in changed:
        after[url] = page_item(url, 1, rnd)
    second_at = catalogs.next_generated_at(SECOND_CLOCK, first.inner["generated_at"],
                                           catalogs.DEFAULT_PARAMETERS["clock_skew_seconds"])
    for url in removed:
        after[url] = removed_item(url, second_at)
    fresh = collection(additions, random.Random(seed + 1), avoid=listed) if additions else {}
    after.update(fresh)
    added = list(fresh)
    second = Catalog(list(after.values()), SECOND_CLOCK, first.inner["generated_at"])
    assert second.inner["generated_at"] == second_at

    touched = changed + added
    if touched or removed:
        second.assert_reference_body((touched or removed)[0])
    out["catalog_entry_octets"] = jcs_octets(second.entry())
    out["page_item_entry_octets"] = spread([jcs_octets(second.item_entry(url)) for url in touched])
    out["removed_item_entry_octets"] = spread([jcs_octets(second.item_entry(url)) for url in removed])

    files, octets = pull(second, first.files)
    out["pull_files"] = files
    out["pull_octets"] = octets
    out["pull_octets_per_change"] = round(octets / max(1, changes + removals + additions), 1)
    out["tree_files_named"] = len(second.files)
    out["tree_files_served_with_replaced"] = len(set(first.files) | set(second.files))

    if timings:
        started = time.perf_counter()
        SIGNING_KEY.sign(items.jcs(second.inner))
        clock["sign_catalog_ms"] = (time.perf_counter() - started) * 1000
        started = time.perf_counter()
        assert items.root_string(list(after.values())) == second.inner["root"]
        clock["recompute_root_s"] = time.perf_counter() - started
        bodies = [second.item_body(url) for url in touched + removed]
        started = time.perf_counter()
        for body in bodies:
            assert items.proof_disposition(body["item"], body["proof"], second.inner) == "accepted"
        clock["verify_proof_us"] = (time.perf_counter() - started) / max(1, len(bodies)) * 1e6
        out["timings"] = {name: round(value, 3) for name, value in clock.items()}
    return out


def parse_round(text):
    values = tuple(int(part) for part in text.split(","))
    if len(values) != 4 or min(values) < 0 or values[0] < 1 or values[1] + values[2] > values[0]:
        raise argparse.ArgumentTypeError("a round is N,changed,removed,added with 1 <= N and changed + removed <= N")
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("rounds", nargs="*", type=parse_round, metavar="N,changed,removed,added")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--timings", action="store_true")
    arguments = parser.parse_args()
    for round_ in arguments.rounds or [parse_round(text) for text in DEFAULT_ROUNDS]:
        print(json.dumps(measure(*round_, arguments.seed, arguments.timings)), flush=True)


if __name__ == "__main__":
    main()
