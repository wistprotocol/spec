#!/usr/bin/env python3
import argparse
import json
import random

import catalogs
import change_lists
import items
import measure_catalog_costs as costs

DEFAULT_ROUNDS = ["100,10,1,1", "10000,1,0,0", "10000,10,1,1,4", "10000,1000,10,10,4", "100000,10,1,1",
                  "100000,10000,100,100", "1000000,10,1,1", "1000000,1000,10,10"]
BASIS = {
    "files": "catalog.json and every file the pull fetches, Payloads excluded",
    "octets": "JCS of the Catalog envelope as catalog.json, plus the octets of every tree file or change list fetched",
    "walk": "tree files the Aggregator does not hold from its walk of the Catalog whose list it holds",
    "change_list": "the change lists read_chain reads, from the held list of the Catalog it holds",
    "list_octets_per_differing_item": "octets of the change lists alone over the Items in their items and dropped",
}


def clock_of(round_number):
    return "2026-09-27T%02d:00:00Z" % (12 + round_number)


def first_round(n, changes, removals, additions, seed):
    rnd = random.Random(seed)
    listed = costs.collection(n, rnd)
    first = costs.Catalog(list(listed.values()), costs.FIRST_CLOCK)
    if n <= costs.PROBE_MAX:
        first.assert_reference_body(first.ordered[rnd.randrange(n)]["url"])
    urls = list(listed)
    rnd.shuffle(urls)
    changed, removed = urls[:changes], urls[changes:changes + removals]
    after = dict(listed)
    for url in changed:
        after[url] = costs.page_item(url, 1, rnd)
    second_at = catalogs.next_generated_at(costs.SECOND_CLOCK, first.inner["generated_at"],
                                           catalogs.DEFAULT_PARAMETERS["clock_skew_seconds"])
    for url in removed:
        after[url] = costs.removed_item(url, second_at)
    fresh = costs.collection(additions, random.Random(seed + 1), avoid=listed) if additions else {}
    after.update(fresh)
    second = costs.Catalog(list(after.values()), costs.SECOND_CLOCK, first.inner["generated_at"])
    assert second.inner["generated_at"] == second_at
    return rnd, first, after, second


def next_round(rnd, listed, previous, round_number, changes, removals, additions, seed):
    urls = [url for url, item in listed.items() if items.kind(item) == "page"]
    rnd.shuffle(urls)
    changed, removed = urls[:changes], urls[changes:changes + removals]
    after = dict(listed)
    for url in changed:
        after[url] = costs.page_item(url, round_number, rnd)
    generated_at = catalogs.next_generated_at(clock_of(round_number), previous.inner["generated_at"],
                                              catalogs.DEFAULT_PARAMETERS["clock_skew_seconds"])
    for url in removed:
        after[url] = costs.removed_item(url, generated_at)
    if additions:
        after.update(costs.collection(additions, random.Random(seed + round_number), avoid=listed))
    catalog = costs.Catalog(list(after.values()), clock_of(round_number), previous.inner["generated_at"])
    assert catalog.inner["generated_at"] == generated_at
    return after, catalog


def written(previous, catalog):
    return change_lists.write(previous.id, previous.ordered, catalog.id, catalog.ordered)


def unwritten_octets(previous, catalog):
    dropped, changed = change_lists.difference(previous.ordered, catalog.ordered)
    return len(items.jcs({"previous": previous.id, "catalog": catalog.id, "dropped": dropped, "items": changed}))


def differing(previous, catalog):
    dropped, changed = change_lists.difference(previous.ordered, catalog.ordered)
    return len(dropped) + len(changed)


def compare(held, catalog, served):
    walk_files, walk_octets = costs.pull(catalog, held.files)
    catalog_octets = costs.jcs_octets(catalog.envelope)
    expected = [items.item_id(item) for item in catalog.ordered]
    out = {"walk_files": walk_files, "walk_octets": walk_octets}
    obtained = change_lists.obtain(catalog.inner, {held.id: held.ordered}, served, held.files, catalog.files)
    if obtained["chain"] == "accepted":
        assert obtained["list"] == expected
        assert obtained["previous"] == held.id
        files, octets = len(obtained["lists_read"]) + 1, obtained["octets"] + catalog_octets
        out.update({"chain": "accepted", "lists_read": len(obtained["lists_read"]),
                    "change_list_files": files, "change_list_octets": octets,
                    "octets_ratio": round(octets / walk_octets, 4)})
    else:
        assert obtained["chain"] == "discarded" and obtained["report"]["condition"] == "fetch"
        walked = obtained["walk"]
        assert walked["list"] == expected
        assert len(walked["tree_files_fetched"]) == walk_files - 1
        assert sum(len(catalog.files[d]) for d in walked["tree_files_fetched"]) == walk_octets - catalog_octets
        out.update({"chain": "discarded at fetch, the walk follows", "lists_read": len(obtained["lists_read"]),
                    "pull_files": walk_files + len(obtained["lists_read"]),
                    "pull_octets": walk_octets + obtained["octets"]})
    return out


def measure(n, changes, removals, additions, rounds, seed):
    rnd, first, listed, second = first_round(n, changes, removals, additions, seed)
    out = {"N": n, "changed": changes, "removed": removals, "added": additions,
           "change_list_cap_bytes": change_lists.CHANGE_LIST_CAP_BYTES}
    octets = written(first, second)
    count = differing(first, second)
    assert count == changes + removals + additions
    out["items_differing"] = count
    if octets is None:
        size = unwritten_octets(first, second)
        assert size > change_lists.CHANGE_LIST_CAP_BYTES
        out.update({"change_list_written": False, "change_list_would_hold_octets": size,
                    "change_list_would_hold_octets_per_differing_item": round(size / max(1, count), 1)})
        served = {}
    else:
        out.update({"change_list_written": True, "change_list_file_octets": len(octets),
                    "list_octets_per_differing_item": round(len(octets) / max(1, count), 1)})
        served = {change_lists.name_of(second.id): octets}
    out.update(compare(first, second, served))
    if rounds > 1:
        served_lists = dict(served)
        sizes = [None if octets is None else len(octets)]
        previous = second
        for round_number in range(2, rounds + 1):
            listed, catalog = next_round(rnd, listed, previous, round_number, changes, removals, additions, seed)
            octets = written(previous, catalog)
            sizes.append(None if octets is None else len(octets))
            if octets is not None:
                served_lists[change_lists.name_of(catalog.id)] = octets
            previous = catalog
        count = differing(first, previous)
        chain = {"rounds": rounds, "change_list_file_octets": sizes, "items_differing": count}
        if None not in sizes:
            chain["list_octets_per_differing_item"] = round(sum(sizes) / max(1, count), 1)
        chain.update(compare(first, previous, served_lists))
        out["chain_of_rounds"] = chain
    return out


def parse_round(text):
    values = tuple(int(part) for part in text.split(","))
    if len(values) == 4:
        values += (1,)
    if (len(values) != 5 or min(values) < 0 or values[0] < 1 or values[4] < 1
            or values[4] > change_lists.CHANGE_CHAIN_MAX or values[1] + values[2] > values[0]):
        raise argparse.ArgumentTypeError(
            "a round is N,changed,removed,added[,rounds] with 1 <= N, changed + removed <= N"
            " and 1 <= rounds <= change_chain_max")
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("rounds", nargs="*", type=parse_round, metavar="N,changed,removed,added[,rounds]")
    parser.add_argument("--seed", type=int, default=7)
    arguments = parser.parse_args()
    print(json.dumps({"basis": BASIS}), flush=True)
    for round_ in arguments.rounds or [parse_round(text) for text in DEFAULT_ROUNDS]:
        print(json.dumps(measure(*round_, arguments.seed)), flush=True)


if __name__ == "__main__":
    main()
