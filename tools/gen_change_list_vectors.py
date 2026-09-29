#!/usr/bin/env python3
import calendar
import copy
import hashlib
import json
import pathlib
import time

import catalogs
import change_lists
import items
import tree_files

ROOT = pathlib.Path(__file__).resolve().parents[1]
WIST2 = ROOT / "vectors" / "wist2"

CAP = change_lists.CHANGE_LIST_CAP_BYTES
CHAIN_MAX = change_lists.CHANGE_CHAIN_MAX
DAY = 86400
START = "2026-10-01T12:00:00Z"
OBSERVED = "2026-09-20T08:00:00Z"
BUCKET_CAPACITY = 2
PUBLISHER = {"domain": "example.com", "subdomain_scope": ["www.example.com", "blog.example.com"],
             "collections": [{"name": "journal", "scope": [{"url": "https://example.com/journal/",
                                                            "match": "prefix"}]}]}
LARGE_PREFIX = "https://example.com/journal/large/"
LARGE_ITEMS = 70


def seconds(instant):
    return calendar.timegm(time.strptime(instant, "%Y-%m-%dT%H:%M:%SZ"))


def stamp(value):
    return catalogs.log_timestamp(value)


def at(days=0, extra=0):
    return stamp(seconds(START) + days * DAY + extra)


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")


def salt_for(label):
    return items.rules.b64u(hashlib.sha256(("change list salt " + label).encode()).digest()[:16])


class Payloads:
    def __init__(self):
        self.by_id = {}

    def page(self, url, observed_at, label=None):
        label = label or url
        publication = {"url": url, "lang": "en", "modified": observed_at,
                       "content": {"extract": f"Text of {label}.", "links": {"total": 0, "urls": []},
                                   "summary": {"title": f"Title {label}"}}}
        item, payload = items.new_page_item("example.com", publication, salt_for(label))
        self.by_id[items.payload_name(item)] = payload
        return item

    def of(self, *lists):
        wanted = set()
        for listed in lists:
            wanted |= {items.payload_name(i) for i in listed if isinstance(i, dict) and items.kind(i) == "page"}
        return {name: self.by_id[name] for name in sorted(wanted)}


def removed(url, observed_at):
    return {"publisher": "example.com", "url": url, "observed_at": observed_at, "removed": True}


def url(i):
    return f"https://example.com/journal/c{i:03d}"


def large_set(total_octets):
    template = {"previous": "sha256:" + "0" * 64, "catalog": "sha256:" + "0" * 64, "dropped": []}

    def entries(fills):
        return [[f"{LARGE_PREFIX}{i:03d}/", fill] for i, fill in enumerate(fills)]

    def octets(fills):
        return len(items.jcs({**template, "items": items.in_list_order(expand_set(entries(fills)))}))

    fills = [1] * LARGE_ITEMS
    per, rest = divmod(total_octets - octets(fills), LARGE_ITEMS)
    fills = [1 + per + (1 if i < rest else 0) for i in range(LARGE_ITEMS)]
    assert octets(fills) == total_octets
    return {"publisher": "example.com", "observed_at": OBSERVED, "urls": entries(fills)}


def expand_set(entries, observed_at=OBSERVED):
    return [removed(prefix + "x" * fill, observed_at) for prefix, fill in entries]


LARGE = {"at_cap": large_set(CAP), "above_cap": large_set(CAP + 1)}
LARGE_ITEMS_OF = {label: items.in_list_order(expand_set(s["urls"], s["observed_at"])) for label, s in LARGE.items()}
for _listed in LARGE_ITEMS_OF.values():
    assert all(len(items.jcs(i)) <= items.ITEM_BOUND_OCTETS for i in _listed)
LARGE_NOTE = (
    "`large_item_sets` describes two sets of Items too large to spell out: each Item is {publisher, observed_at, "
    "url: prefix followed by fill copies of the letter x, removed: true} for each [prefix, fill] of `urls`. A "
    "string element of an Item list stands for every Item of the large set it names. A change list whose "
    "`items` is such a string (compact form) is the JCS serialization of its object with `items` replaced by "
    "that set's Items in strictly ascending octet order of key; for any previous, catalog and an empty dropped the "
    "file is 1 048 576 octets for `at_cap` and 1 048 577 for `above_cap`.")


def expand(listed):
    out = []
    for element in listed:
        out.extend(LARGE_ITEMS_OF[element] if isinstance(element, str) else [element])
    return items.in_list_order(out)


def catalog_of(listed, generated_at, collection="journal"):
    full = expand(listed)
    tree, files = tree_files.write_tree(full, BUCKET_CAPACITY)
    inner = {"wist_version": "1.0.0", "publisher": "example.com", "collection": collection,
             "generated_at": generated_at, "size": len(full), "root": items.root_string(full), "tree": tree}
    return inner, files


NESTING = 100


def max_depth(value):
    if isinstance(value, dict):
        return 1 + max((max_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((max_depth(v) for v in value), default=0)
    return 0


def texts(files):
    return {name: octets.decode("utf-8") for name, octets in sorted(files.items())}


def ids(listed):
    return [items.item_id(i) for i in expand(listed)]


def change_list_vectors():
    book = Payloads()
    held = items.in_list_order([book.page(url(0), OBSERVED), book.page(url(1), OBSERVED), book.page(url(2), OBSERVED),
                                removed(url(3), OBSERVED)])
    by_url = {i["url"]: i for i in held}
    revised = book.page(url(1), at(-1), label="c001 revised")
    added = book.page(url(4), at(-1))
    previous_id = "sha256:" + hashlib.sha256(b"change list form previous").hexdigest()
    catalog_id = "sha256:" + hashlib.sha256(b"change list form catalog").hexdigest()
    other_id = "sha256:" + hashlib.sha256(b"change list form other").hexdigest()
    name = change_lists.name_of(catalog_id)
    dropped = sorted(items.item_key(u).hex() for u in (url(0), url(3)))
    elements = items.in_list_order([revised, added])
    reference = {"previous": previous_id, "catalog": catalog_id, "dropped": dropped, "items": elements}
    cases = []

    def form(case_name, text, expected, file=name):
        octets = text.encode("utf-8") if isinstance(text, str) else text
        got = change_lists.form_disposition(octets, file)
        assert got == expected, (case_name, got)
        cases.append({"name": case_name, "file": file, "text": octets.decode("utf-8"), "expected": got})

    def jcs_text(obj):
        return items.jcs(obj).decode("utf-8")

    def varied(**members):
        obj = copy.deepcopy(reference)
        for member, value in members.items():
            if value is None:
                del obj[member]
            else:
                obj[member] = value
        return jcs_text(obj)

    reference_text = jcs_text(reference)
    form("change list of the form", reference_text, "accepted")
    form("change list with both arrays empty", varied(dropped=[], items=[]), "accepted")
    form("change list whose items are objects with a string url and no other member",
         varied(items=[{"url": e["url"]} for e in elements]), "accepted")
    form("change list served under the name of another Catalog ID than its catalog", reference_text, "form",
         file=change_lists.name_of(other_id))
    form("change list with a space after a colon", reference_text.replace('"previous":', '"previous": ', 1), "form")
    form("change list followed by a line feed", reference_text + "\n", "form")
    form("change list with previous after catalog",
         '{"catalog":' + json.dumps(catalog_id) + ',"previous":' + json.dumps(previous_id)
         + reference_text[len('{"previous":' + json.dumps(previous_id) + ',"catalog":' + json.dumps(catalog_id)):], "form")
    form("change list with the member previous repeated",
         '{"previous":' + json.dumps(other_id) + "," + reference_text[1:], "form")
    form("change list whose url escapes a lone surrogate",
         reference_text.replace(elements[0]["url"], elements[0]["url"] + "\\ud800", 1), "form")
    form("change list whose url escapes a slash",
         reference_text.replace(elements[0]["url"], elements[0]["url"].replace("/", "\\/"), 1), "form")
    form("change list spelling payload.bytes with a fraction",
         reference_text.replace('"bytes":' + str(elements[0]["payload"]["bytes"]),
                                '"bytes":' + str(elements[0]["payload"]["bytes"]) + ".0", 1), "form")
    form("change list that is an array", jcs_text([previous_id, catalog_id, dropped, elements]), "form")
    form("change list without dropped", varied(dropped=None), "form")
    form("change list without items", varied(items=None), "form")
    form("change list with a member size", jcs_text({**reference, "size": 2}), "form")
    form("previous without its sha256: prefix", varied(previous=previous_id[len("sha256:"):]), "form")
    form("previous in uppercase hexadecimal", varied(previous="sha256:" + previous_id[len("sha256:"):].upper()), "form")
    form("previous of 63 digits", varied(previous=previous_id[:-1]), "form")
    form("previous a number", varied(previous=7), "form")
    form("catalog in uppercase hexadecimal", varied(catalog="sha256:" + name.upper()), "form")
    form("dropped an object", varied(dropped={"0": dropped[0]}), "form")
    form("dropped key a number", varied(dropped=[7]), "form")
    form("dropped key in uppercase hexadecimal", varied(dropped=[dropped[0].upper(), dropped[1]]), "form")
    form("dropped key with a sha256: prefix", varied(dropped=["sha256:" + dropped[0], dropped[1]]), "form")
    form("dropped key of 63 digits", varied(dropped=[dropped[0][:-1], dropped[1]]), "form")
    form("dropped keys in descending order", varied(dropped=list(reversed(dropped))), "form")
    form("dropped key repeated", varied(dropped=[dropped[0], dropped[0]]), "form")
    form("items an object", varied(items={"0": elements[0]}), "form")
    form("items element a string", varied(items=[elements[0]["url"]]), "form")
    form("items element null", varied(items=[None]), "form")
    form("items element without url", varied(items=[{"href": elements[0]["url"]}]), "form")
    form("items element whose url is a number", varied(items=[{"url": 7}]), "form")
    form("items in descending order of key", varied(items=list(reversed(elements))), "form")
    form("items holding two elements of one key", varied(items=[elements[0], elements[0]]), "form")
    by_url_order = sorted([revised, added, book.page(url(5), at(-1))], key=lambda i: i["url"])
    assert by_url_order != items.in_list_order(by_url_order)
    form("items in ascending order of url but not of key", varied(items=by_url_order), "form")
    form("items in ascending order of key but not of url", varied(items=items.in_list_order(by_url_order)),
         "accepted")
    form("key both dropped and listed", varied(dropped=sorted(dropped + [items.item_key(url(4)).hex()])), "form")
    nested = []
    for _ in range(NESTING - 4):
        nested = [nested]
    deep_text = varied(items=[{"url": elements[0]["url"], "z": nested}])
    assert max_depth(json.loads(deep_text)) == NESTING
    form("items element holding arrays nested to a depth of 100 in the file", deep_text, "accepted")
    finite_text = varied(items=[{"n": 1, "url": elements[0]["url"]}])
    assert finite_text.count('"n":1,') == 1
    form("items element holding the number 1", finite_text, "accepted")
    form("items element holding the number 1e400, beyond the finite range",
         finite_text.replace('"n":1,', '"n":1e400,'), "form")

    application = []

    def applied(case_name, listed, change):
        octets = items.jcs(change)
        parsed = change_lists.parse(octets, change_lists.name_of(change["catalog"]))
        result = change_lists.apply(listed, parsed)
        application.append({"name": case_name, "list": listed, "change_list": octets.decode("utf-8"),
                            "expected": {"list": ids(result), "size": len(result),
                                         "root": items.root_string(result)}})
        return result

    def change(dropped_urls=(), new=()):
        return {"previous": previous_id, "catalog": catalog_id,
                "dropped": sorted(items.item_key(u).hex() for u in dropped_urls),
                "items": items.in_list_order(list(new))}

    result = applied("a new Item enters, an Item of another Item ID replaces the held one, and Items leave",
                     held, change([url(0), url(3)], [revised, added]))
    assert [i["url"] for i in result] == [i["url"] for i in items.in_list_order([by_url[url(2)], revised, added])]
    applied("a dropped key under which the list holds no Item changes nothing", held, change([url(9)]))
    applied("an element equal to the held Item changes nothing", held, change(new=[by_url[url(2)]]))
    applied("a dropped Item of kind page leaves the list", held, change([url(0)]))
    applied("an Item of kind removed that left the list after removal_retention_days, stated in dropped", held,
            change([url(3)]))
    applied("an Item of kind removed enters the list as an element in place of an Item of kind page", held,
            change(new=[removed(url(2), at())]))
    applied("a change list with both arrays empty changes nothing", held, change())
    applied("a change list applied to the empty list", [], change([url(0)], [added]))
    applied("every Item dropped gives the empty list", held, change([i["url"] for i in held]))

    return {"note": (
        "ADR-0053 Change lists: the form of a change list and its application. `form_cases`: `text` is the file's "
        "octets as UTF-8 text and `file` the 64 hexadecimal digits of its name; `expected` is \"accepted\" or "
        "\"form\". The octets are of the form when they are valid JCS input (UTF-8, no repeated member name, "
        "strings of Unicode scalar values, numbers in the finite range), parse to an object of exactly the "
        "members previous, catalog, dropped and items, previous and catalog each \"sha256:\" followed by 64 lowercase "
        "hexadecimal digits, dropped an array of strings of 64 lowercase hexadecimal digits in strictly "
        "ascending order, items an array of objects each with a string member url in strictly ascending octet "
        "order of key (SHA-256(JCS([\"page\", url]))), no key of dropped equal to the key of an element, the "
        "octets equal the JCS serialization of that object, and catalog is \"sha256:\" followed by `file`. An "
        "element is not judged as an Item here. No case nests deeper than 100 levels, counting the outer "
        "object as one. Each case that fails is a twin of an accepted one differing in "
        "the respect its name gives. `application_cases`: `list` is an Item list, `change_list` the text of a "
        "change list of the form; the change list is applied: every Item under a key of dropped leaves, "
        "whatever its kind, and each element of items takes the place of the Item under its key or enters. "
        "`expected` gives the Item IDs (\"sha256:\" + hex(SHA-256(JCS(item)))) of the result in ascending octet "
        "order of key, its number of Items and its root (ADR-0052 Items). `payloads` carries the Payload of "
        "each Item of kind page that appears as an object, keyed by the digits of its Item ID; no rule here "
        "reads it."),
        "form_cases": cases, "application_cases": application, "payloads": book.of(*(
            [c["list"] for c in application]))}


def sequence(book, steps_count, spacing=DAY):
    lists = [items.in_list_order([book.page(url(0), OBSERVED), book.page(url(1), OBSERVED),
                                  book.page(url(2), OBSERVED), removed(url(3), OBSERVED)])]
    removed_queue = [url(3)]
    for k in range(1, steps_count):
        generated = stamp(seconds(START) + k * spacing)
        by_url = {i["url"]: i for i in lists[-1]}
        by_url[url(3 + k)] = book.page(url(3 + k), stamp(seconds(generated) - 3600))
        pages = sorted(u for u, i in by_url.items() if items.kind(i) == "page" and u != url(3 + k))
        if k % 3 == 0:
            gone = pages[0]
            by_url[gone] = removed(gone, generated)
            removed_queue.append(gone)
        elif k % 3 == 1:
            target = pages[-1]
            by_url[target] = book.page(target, stamp(seconds(generated) - 1800), label=f"{target} at step {k}")
        elif removed_queue:
            del by_url[removed_queue.pop(0)]
        lists.append(items.in_list_order(list(by_url.values())))
    return lists


def build_catalogs(lists, start_day=0):
    out = []
    for k, listed in enumerate(lists):
        inner, files = catalog_of(listed, at(start_day + k))
        out.append({"catalog": inner, "id": items.catalog_id(inner), "list": listed, "files": files})
    return out


def serving_vectors():
    book = Payloads()
    write_cases, sequence_cases = [], []

    def write_case(case_name, served, new, expected_written, derived=None):
        new_full = expand(new["list"])
        if served is None:
            octets = change_lists.write(None, None, new["id"], new_full)
        else:
            octets = change_lists.write(served["id"], expand(served["list"]), new["id"], new_full)
        assert (octets is not None) == expected_written, case_name
        if octets is None:
            expected = {"written": False}
        else:
            expected = {"written": True, "name": change_lists.name_of(new["id"]), "octets": len(octets),
                        "sha256": hashlib.sha256(octets).hexdigest()}
            if len(octets) <= 65536:
                expected["text"] = octets.decode("utf-8")
        entry = {"name": case_name,
                 "served": None if served is None else {"catalog": served["catalog"], "list": served["list"]},
                 "new": {"catalog": new["catalog"], "list": new["list"]}, "expected": expected}
        if derived is not None:
            entry["derived"] = derived
        write_cases.append(entry)
        return octets

    def entry(listed, day, generated_at=None):
        inner, _ = catalog_of(listed, generated_at or at(day))
        return {"catalog": inner, "id": items.catalog_id(inner), "list": listed}

    a, b, c = (book.page(url(20), OBSERVED), book.page(url(21), OBSERVED), book.page(url(22), OBSERVED))
    gone = removed(url(23), OBSERVED)
    served_list = items.in_list_order([a, b, c, gone])
    served = entry(served_list, 0)
    served_payloads = {items.item_id(i): book.by_id[items.payload_name(i)] for i in (a, b, c)}
    publications = [
        {"url": url(20), "lang": "en", "modified": OBSERVED, "content": served_payloads[items.item_id(a)]["content"]},
        {"url": url(21), "lang": "en", "modified": at(0, 60), "content": {
            "extract": "Text of c021, revised.", "links": {"total": 0, "urls": []}, "summary": {"title": "Title c021"}}},
        {"url": url(24), "lang": "en", "modified": at(0, 60), "content": {
            "extract": "Text of c024.", "links": {"total": 0, "urls": []}, "summary": {"title": "Title c024"}}}]
    derived = items.derive_list(served_list, served_payloads, publications, PUBLISHER, "journal", at(1),
                                {p["url"]: salt_for("derived " + p["url"]) for p in publications}, "1.0.0")
    for item, payload in derived["payloads"].items():
        book.by_id[item[len("sha256:"):]] = payload
    new_list = derived["list"]
    octets = write_case("an unchanged Item is not listed; a revised, a new and a removed Item are; nothing is dropped",
                        served, entry(new_list, 1), True)
    parsed = change_lists.parse(octets)
    assert parsed["dropped"] == [] and {e["url"] for e in parsed["items"]} == {url(21), url(22), url(24)}
    write_case("a Catalog whose list is the served one holds both arrays empty", served, entry(served_list, 1), True)
    write_case("a Catalog signed for a Collection with no served Catalog has no change list", None,
               entry(served_list, 0), False)
    write_case("a dropped Item of kind page", served, entry([a, b, gone], 1), True)

    retention_end = seconds(OBSERVED) + items.REMOVAL_RETENTION_DAYS * DAY
    for offset, dropped in ((0, True), (-1, False)):
        instant = stamp(retention_end + offset)
        kept = items.derive_list(served_list, served_payloads, publications[:1] + [
            {"url": u, "lang": "en", "modified": OBSERVED, "content": served_payloads[items.item_id(i)]["content"]}
            for u, i in ((url(21), b), (url(22), c))], PUBLISHER, "journal", instant, {}, "1.0.0")["list"]
        assert (gone in kept) != dropped
        case_name = ("an Item of kind removed that left the list after removal_retention_days, stated in dropped"
                     if dropped else "an Item of kind removed one second before removal_retention_days ends, "
                                     "kept, and both arrays empty")
        octets = write_case(case_name, served, entry(kept, 0, instant), True, derived={"generated_at": instant})
        assert change_lists.parse(octets)["dropped"] == ([items.item_key(url(23)).hex()] if dropped else [])

    small = items.in_list_order([a, b])
    small_served = entry(small, 0)
    write_case("a difference whose change list is change_list_cap_bytes octets", small_served,
               entry(small + ["at_cap"], 1), True)
    write_case("a difference whose change list would be one octet above change_list_cap_bytes", small_served,
               entry(small + ["above_cap"], 1), False)

    spacing = 36000
    served_delay = 600

    def sequence_case(case_name, lists, check, stops=(), extra_clocks=(), declaration_stops_at=None):
        steps = []
        for k, listed in enumerate(lists):
            generated = seconds(START) + k * spacing
            inner, _ = catalog_of(listed, stamp(generated))
            steps.append({"catalog": inner, "id": items.catalog_id(inner), "list": listed,
                          "served_at": generated + served_delay})
        names = [change_lists.name_of(s["id"]) for s in steps]
        stop_list = [(names[k], steps[j]["served_at"] + offset) for k, j, offset in stops]
        clocks = sorted({s["served_at"] for s in steps} | {c(steps) for c in extra_clocks})
        got, written = change_lists.serve_timeline(
            [{"id": s["id"], "list": expand(s["list"]), "served_at": s["served_at"]} for s in steps], stop_list,
            clocks, declaration_stops_at and declaration_stops_at(steps))
        by_clock = {clock: g for clock, g in zip(clocks, got)}
        check(by_clock, steps, names)
        entry = {"name": case_name,
                 "steps": [{"catalog": s["catalog"], "list": s["list"], "served_at": stamp(s["served_at"])}
                           for s in steps],
                 "stop_serving": [{"change_list": n, "at": stamp(t)} for n, t in stop_list],
                 "declaration_stops_at": (stamp(declaration_stops_at(steps)) if declaration_stops_at else None),
                 "expected": {"written": [n if n in written else None for n in names],
                              "clocks": [{"clock": stamp(clock), **g} for clock, g in zip(clocks, got)]}}
        sequence_cases.append(entry)

    long_lists = sequence(book, CHAIN_MAX + 3, spacing)
    replaced = change_lists.REPLACED_FILE_SECONDS

    def end_of(k):
        return lambda steps: steps[k]["served_at"] + replaced

    def before_end_of(k):
        return lambda steps: steps[k]["served_at"] + replaced - 1

    def served_at(k, offset=0):
        return lambda steps: steps[k]["served_at"] + offset

    def long_check(by, steps, names):
        at = [s["served_at"] for s in steps]
        assert by[at[0]] == {"must_serve": [], "may_serve": [], "must_not_serve": []}
        assert by[at[CHAIN_MAX]]["must_serve"] == sorted(names[1:CHAIN_MAX + 1])
        assert by[at[CHAIN_MAX + 1]]["must_serve"] == sorted(names[1:CHAIN_MAX + 2])
        assert by[at[CHAIN_MAX + 2]]["must_serve"] == sorted(names[1:CHAIN_MAX + 3])
        assert names[1] in by[at[CHAIN_MAX + 1] + replaced - 1]["must_serve"]
        assert by[at[CHAIN_MAX + 1] + replaced]["may_serve"] == [names[1]]
        assert names[2] in by[at[CHAIN_MAX + 2] + replaced - 1]["must_serve"]
        assert by[at[CHAIN_MAX + 2] + replaced]["may_serve"] == sorted(names[1:3])

    sequence_case("nineteen Catalogs: the chain grows to change_chain_max lists, and each list a new Catalog puts "
                  "out of the first change_chain_max stays served until replaced_file_seconds after that Catalog "
                  "began to be served", long_lists, long_check,
                  extra_clocks=(before_end_of(CHAIN_MAX + 1), end_of(CHAIN_MAX + 1), before_end_of(CHAIN_MAX + 2),
                                end_of(CHAIN_MAX + 2), served_at(CHAIN_MAX + 2, 3600)))

    def stop_inside_check(by, steps, names):
        at = steps[CHAIN_MAX + 2]["served_at"]
        assert by[at + 3600] == {"must_serve": sorted(names[2:CHAIN_MAX + 3]), "may_serve": [],
                                 "must_not_serve": [names[1]]}
        assert by[at - 1]["must_serve"] == sorted(names[1:CHAIN_MAX + 2])

    sequence_case("a list inside its replaced_file_seconds that the Publisher must stop serving is removed at once",
                  long_lists, stop_inside_check, stops=((1, CHAIN_MAX + 2, 3600),),
                  extra_clocks=(served_at(CHAIN_MAX + 2, -1), served_at(CHAIN_MAX + 2, 3600)))

    no_list_lists = sequence(book, CHAIN_MAX + 2, spacing)
    no_list_lists[-1] = no_list_lists[-1] + ["above_cap"]

    def no_list_check(by, steps, names):
        at = steps[CHAIN_MAX + 1]["served_at"]
        assert by[at - 1]["must_serve"] == sorted(names[1:CHAIN_MAX + 1])
        assert by[at] == {"must_serve": [], "may_serve": sorted(names[1:CHAIN_MAX + 1]), "must_not_serve": []}

    sequence_case("the lists behind a Catalog with no change list are not served for replaced_file_seconds",
                  no_list_lists, no_list_check, extra_clocks=(served_at(CHAIN_MAX + 1, -1),))

    first = long_lists[0]
    after = [first + ["above_cap"]]
    for k in (1, 2):
        target = url(k)
        kept_objects = [i for i in after[-1] if not isinstance(i, str) and i["url"] != target]
        after.append(items.in_list_order(kept_objects + [book.page(target, stamp(seconds(START) + k * spacing),
                                                                   label=f"{target} behind")]) + ["above_cap"])

    def behind_check(by, steps, names):
        at = [s["served_at"] for s in steps]
        assert by[at[1]] == {"must_serve": [], "may_serve": [], "must_not_serve": []}
        assert by[at[2]]["must_serve"] == [names[2]]
        assert by[at[3]] == {"must_serve": sorted(names[2:4]), "may_serve": [], "must_not_serve": []}

    sequence_case("a Catalog whose difference would exceed change_list_cap_bytes has no change list and ends the "
                  "chain of the Catalogs after it", [first] + after, behind_check)

    def stopped_check(by, steps, names):
        at = [s["served_at"] for s in steps]
        assert by[at[4]]["must_serve"] == sorted(names[1:5])
        assert by[at[5]] == {"must_serve": sorted(names[4:6]), "may_serve": sorted(names[1:3]),
                             "must_not_serve": [names[3]]}
        assert by[at[7]] == {"must_serve": sorted(names[4:8]), "may_serve": sorted(names[1:3]),
                             "must_not_serve": [names[3]]}

    sequence_case("a list in the middle of the chain the Publisher must stop serving ends the chain: the lists "
                  "behind it may be served, those in front of it stay served, and the chain grows again in front",
                  sequence(book, 8, spacing), stopped_check, stops=((3, 5, 0),))

    declaration_lists = sequence(book, CHAIN_MAX + 2, spacing)

    def declaration_check(by, steps, names):
        stop = steps[CHAIN_MAX + 1]["served_at"] + 3600
        obliged = sorted(names[1:CHAIN_MAX + 2])
        assert by[stop]["must_serve"] == obliged
        assert by[steps[CHAIN_MAX + 1]["served_at"] + replaced]["must_serve"] == obliged
        assert by[stop + replaced - 1]["must_serve"] == obliged
        assert by[stop + replaced] == {"must_serve": [], "may_serve": obliged, "must_not_serve": []}

    sequence_case("the change lists the Publisher is obliged to serve when the served Declaration stops naming the "
                  "Collection stay served for replaced_file_seconds from that instant", declaration_lists,
                  declaration_check,
                  extra_clocks=(served_at(CHAIN_MAX + 1, 3600), end_of(CHAIN_MAX + 1),
                                served_at(CHAIN_MAX + 1, 3600 + replaced - 1), served_at(CHAIN_MAX + 1, 3600 + replaced)),
                  declaration_stops_at=served_at(CHAIN_MAX + 1, 3600))

    return {"note": (
        "ADR-0053 What a Publisher serves. Change list names are the 64 hexadecimal digits of the Catalog ID "
        "(\"sha256:\" + hex(SHA-256(JCS(catalog)))) the list leads to. `write_cases`: `served` is the served "
        "Catalog (an inner object) with its Item list, or null for a Collection with no served Catalog; `new` "
        "is the Catalog signed with its list. The change list has previous the served Catalog ID, catalog the "
        "new Catalog ID, items every Item of the new list under whose key (SHA-256(JCS([\"page\", url]))) the "
        "served list holds no Item or an Item of another Item ID, in ascending octet order of key, and dropped "
        "the lowercase hexadecimal key of every Item of the served list under whose key the new list holds "
        "none, in ascending order; the file is the JCS serialization of that object. None is written for a "
        "Collection with no served Catalog or where the file would hold more than change_list_cap_bytes, "
        "1 048 576, octets. `expected` is {written: false} or {written: true, name, octets, sha256 (hex "
        "SHA-256 of the file), text (the file, given when it holds at most 65 536 octets)}. `derived`, where "
        "present, gives the generated_at at which ADR-0052 From publications to Items derived the new list from "
        "the served one: an Item of kind removed observed 180 days of 86 400 seconds before generated_at is "
        "no longer listed. `sequence_cases`: `steps` are the Catalogs a Publisher signs in order, each with "
        "`served_at`, the instant on the Publisher's clock at which it began to be served; each replaces the "
        "one before, which is its previous Catalog, and the first has no served Catalog, so its change list "
        "is written as in `write_cases`. `stop_serving` gives each change list the Publisher must stop "
        "serving from the instant `at` on (supplied, whatever made it stop); `declaration_stops_at` is the "
        "instant at which the Publisher began to serve a Declaration that no longer names the Collection, or "
        "null, and no Catalog is served after it. At an instant, the served Catalog is the last step whose "
        "served_at is at or before it, and a list stopped is one whose `at` is at or before it. The chain of a "
        "Catalog is its change list, then the one leading to that list's previous Catalog, and so on, ending "
        "at a Catalog for which no change list was written or whose change list is stopped. When a step "
        "begins to be served, every list among the first change_chain_max, 16, of the chain of the Catalog "
        "before it (both chains taken with the lists stopped at that instant) that stands in the new Catalog's "
        "chain beyond its first 16 is served in an interval from that served_at up to, not including, "
        "served_at plus replaced_file_seconds, 86 400 seconds; a list that leaves the first 16 otherwise (the "
        "new Catalog has no change list, or a stopped list cuts the chain) has no interval. `expected.written` "
        "gives per step the name of the change list written or null. `expected.clocks` gives, at each clock "
        "(every served_at and the instants the case adds), `must_serve`: the first 16 lists of the served "
        "Catalog's chain and every list inside its interval, less the lists stopped; `must_not_serve`: the "
        "lists written so far that are stopped, removed at once whatever interval they are inside; and "
        "`may_serve`: every other list written so far. At a clock at or after declaration_stops_at, "
        "must_serve is instead the lists that were must_serve at declaration_stops_at, less those stopped at "
        "the clock, while the clock is earlier than declaration_stops_at plus 86 400 seconds, and empty from "
        "then on. Each set is in ascending order of name. " + LARGE_NOTE + " `payloads` "
        "carries the Payload of each Item of kind page that appears as an object, keyed by the digits of its "
        "Item ID; no rule here reads it."),
        "large_item_sets": LARGE, "write_cases": write_cases, "sequence_cases": sequence_cases,
        "payloads": book.of(*[s["list"] for c in sequence_cases for s in c["steps"]],
                            *[w[k]["list"] for w in write_cases for k in ("served", "new") if w[k] is not None])}


def chain_vectors():
    book = Payloads()
    lists = sequence(book, CHAIN_MAX + 2)
    seq = build_catalogs(lists)
    files = {}
    for k in range(1, len(seq)):
        files[change_lists.name_of(seq[k]["id"])] = change_lists.write(
            seq[k - 1]["id"], seq[k - 1]["list"], seq[k]["id"], seq[k]["list"])
    cases = []

    def pull(target, held, served_lists, budget=None, served_tree=True, held_tree=None, other=None, parameters=None):
        held_lists = {s["id"]: s["list"] for s in held}
        got = change_lists.obtain(target["catalog"], held_lists, served_lists,
                                  held_tree or {}, target["files"] if served_tree else {}, budget, parameters)
        member = {"catalog": target["catalog"], "held": held_lists,
                  "held_other_collection": {s["id"]: s["list"] for s in (other or [])},
                  "budget": budget, "parameters": parameters,
                  "change_lists": {n: (o if isinstance(o, dict) else o.decode("utf-8"))
                                   for n, o in sorted(served_lists.items())},
                  "tree_files_held": texts(held_tree or {}),
                  "tree_files_served": texts(target["files"]) if served_tree else {}}
        return member, got

    def case(case_name, *pulls):
        members, outcomes = zip(*pulls)
        cases.append({"name": case_name, "pulls": list(members), "expected": list(outcomes)})
        return outcomes

    def name(k):
        return change_lists.name_of(seq[k]["id"])

    def only(*ks):
        return {name(k): files[name(k)] for k in ks}

    repeat_inner, repeat_files = catalog_of(lists[2], at(2, 3600))
    repeat = {"catalog": repeat_inner, "id": items.catalog_id(repeat_inner), "list": lists[2], "files": repeat_files}
    repeat_file = change_lists.write(seq[2]["id"], lists[2], repeat["id"], lists[2])
    with_repeat = {**files, change_lists.name_of(repeat["id"]): repeat_file}
    (got,) = case("a held list of the Catalog's size and root: nothing is fetched", pull(repeat, [seq[2]], with_repeat))
    assert got["chain"] == "held"
    (got,) = case("the twin holding an earlier list reads the chain", pull(repeat, [seq[1]], with_repeat))
    assert got["chain"] == "accepted" and len(got["lists_read"]) == 2

    for length in (1, 2, CHAIN_MAX):
        (got,) = case(f"chain of {length} change list{'s' if length > 1 else ''}, accepted",
                      pull(seq[length], [seq[0]], files))
        assert got["chain"] == "accepted" and len(got["lists_read"]) == length and got["list"] == ids(lists[length])
    (got,) = case("chain of change_chain_max lists whose last names a held previous Catalog, accepted",
                  pull(seq[CHAIN_MAX + 1], [seq[1]], files))
    assert got["chain"] == "accepted" and len(got["lists_read"]) == CHAIN_MAX
    (got,) = case("chain of change_chain_max lists whose last names a previous Catalog not held: chain, and the walk accepts",
                  pull(seq[CHAIN_MAX + 1], [seq[0]], files))
    assert got["report"]["condition"] == "chain" and got["report"]["change_list"] == seq[2]["id"]
    assert got["walk"]["list"] == ids(lists[CHAIN_MAX + 1])
    broken_last = dict(files)
    broken_last[name(2)] = files[name(2)] + b"\n"
    (got,) = case("chain whose change_chain_max-th list is not of the form and names a previous Catalog not held: form",
                  pull(seq[CHAIN_MAX + 1], [seq[0]], broken_last))
    assert got["report"]["condition"] == "form" and len(got["lists_read"]) == CHAIN_MAX
    (got,) = case("the first list read whose previous Catalog's list is held ends the reading, whatever else is held",
                  pull(seq[3], [seq[0], seq[2]], files))
    assert got["lists_read"] == [seq[3]["id"]] and got["previous"] == seq[2]["id"]

    (got,) = case("a list naming a previous Catalog not held whose own list is not served: fetch, and the walk accepts",
                  pull(seq[2], [seq[0]], only(2)))
    assert got["report"] == {"code": "WIST2-E08", "condition": "fetch", "catalog": seq[2]["id"],
                             "change_list": seq[1]["id"]} and "list" in got["walk"]
    step_at = [seconds(seq[k]["catalog"]["generated_at"]) for k in range(4)]
    stopped_at = change_lists.serve_timeline(
        [{"id": seq[k]["id"], "list": lists[k], "served_at": step_at[k]} for k in range(4)],
        [(name(1), step_at[3])], [step_at[3]])[0][0]
    assert stopped_at["must_serve"] == sorted([name(3), name(2)]) and stopped_at["must_not_serve"] == [name(1)]
    (got,) = case("a previous Catalog behind a list the Publisher had to stop serving: fetch at that list, and the walk "
                  "accepts", pull(seq[3], [seq[0]], {n: files[n] for n in stopped_at["must_serve"] + stopped_at["may_serve"]}))
    assert got["report"] == {"code": "WIST2-E08", "condition": "fetch", "catalog": seq[3]["id"],
                             "change_list": seq[1]["id"]} and got["lists_read"] == [seq[3]["id"], seq[2]["id"]]
    assert got["walk"]["list"] == ids(lists[3])
    (got,) = case("the change list of the Catalog not served: fetch, and the walk refuses without the tree",
                  pull(seq[1], [seq[0]], {}, served_tree=False))
    assert got["report"]["condition"] == "fetch" and got["walk"]["refused"] == "WIST2-E07"
    (got,) = case("the change list of the Catalog not served: fetch, and the walk fetches only the tree files "
                  "not held", pull(seq[1], [seq[0]], {}, held_tree=seq[0]["files"]))
    assert 0 < len(got["walk"]["tree_files_fetched"]) < len(seq[1]["files"])

    misnamed = {name(1): files[name(2)]}
    (got,) = case("a list whose catalog is not the name of its file: form, and the walk accepts",
                  pull(seq[1], [seq[0]], misnamed))
    assert got["report"]["condition"] == "form" and got["report"]["change_list"] == seq[1]["id"]

    own = items.jcs({"previous": seq[1]["id"], "catalog": seq[1]["id"], "dropped": [], "items": []})
    (got,) = case("a list whose previous Catalog is its own Catalog is read change_chain_max times: chain",
                  pull(seq[1], [seq[0]], {name(1): own}))
    assert got["report"]["condition"] == "chain" and got["octets"] == CHAIN_MAX * len(own)
    assert got["lists_read"] == [seq[1]["id"]] * CHAIN_MAX
    swapped = dict(files)
    swapped[name(1)] = items.jcs({**change_lists.parse(files[name(1)]), "previous": seq[2]["id"]})
    (got,) = case("two lists naming each other as previous Catalog: chain at the change_chain_max-th list read",
                  pull(seq[2], [seq[0]], swapped))
    assert got["report"]["condition"] == "chain" and got["report"]["change_list"] == seq[1]["id"]

    first = change_lists.parse(files[name(1)])
    other_item = book.page(first["items"][0]["url"], at(1, -1200), label="another Item")
    other_root = dict(files)
    other_root[name(1)] = items.jcs({**first, "items": items.in_list_order(
        [other_item] + [e for e in first["items"] if e["url"] != other_item["url"]])})
    (got,) = case("a chain whose result has another root: result, and the walk accepts",
                  pull(seq[1], [seq[0]], other_root))
    assert got["report"] == {"code": "WIST2-E08", "condition": "result", "catalog": seq[1]["id"],
                             "change_list": seq[1]["id"]}
    kept_key = next(items.item_key(i["url"]).hex() for i in lists[0]
                    if items.item_key(i["url"]).hex() not in first["dropped"]
                    and i["url"] not in {e["url"] for e in first["items"]})
    other_count = dict(files)
    other_count[name(1)] = items.jcs({**first, "dropped": sorted(first["dropped"] + [kept_key])})
    (got,) = case("a chain whose result has another number of Items: result, and the walk refuses without "
                  "the tree", pull(seq[1], [seq[0]], other_count, served_tree=False))
    assert got["report"]["condition"] == "result" and got["walk"]["refused"] == "WIST2-E07"

    second_bad = dict(files)
    second_bad[name(1)] = items.jcs({**first, "size": len(first["items"])})
    (got,) = case("the second list read carries a member other than the four: form, reported at that list",
                  pull(seq[2], [seq[0]], second_bad))
    assert got["report"]["change_list"] == seq[1]["id"] and got["lists_read"] == [seq[2]["id"], seq[1]["id"]]

    store_inner, _ = catalog_of(lists[1], at(1), collection="store")
    store = {"catalog": store_inner, "id": items.catalog_id(store_inner), "list": lists[1]}
    (got,) = case("an Aggregator that holds no list of the Collection reads no change list and walks",
                  pull(seq[1], [], files, other=[store]))
    assert got["chain"] == "none" and "list" in got["walk"]
    (got,) = case("the twin holding the list of the previous Catalog for the Collection reads the chain", pull(seq[1], [seq[0]], files))
    assert got["chain"] == "accepted"

    big_previous = seq[0]
    for label, accepted in (("at_cap", True), ("above_cap", False)):
        target_list = items.in_list_order(lists[0] + LARGE_ITEMS_OF[label])
        inner, tree = catalog_of(target_list, at(1))
        target = {"catalog": inner, "id": items.catalog_id(inner), "list": target_list, "files": tree}
        octets = items.jcs({"previous": big_previous["id"], "catalog": target["id"], "dropped": [],
                            "items": LARGE_ITEMS_OF[label]})
        assert len(octets) == (CAP if accepted else CAP + 1)
        assert change_lists.write(big_previous["id"], lists[0], target["id"], target_list) == (octets if accepted else None)
        member, got = pull(target, [big_previous], {change_lists.name_of(target["id"]): octets}, served_tree=False)
        member["catalog"] = inner
        member["change_lists"] = {change_lists.name_of(target["id"]): {
            "previous": big_previous["id"], "catalog": target["id"], "dropped": [], "items": label}}
        if accepted:
            assert got["list"] == ids(target_list)
            assert got["chain"] == "accepted" and got["octets"] == CAP
            case("a list of change_list_cap_bytes octets is read and accepted", (member, got))
        else:
            assert got["report"]["condition"] == "size" and got["octets"] == 0
            assert got["walk"]["refused"] == "WIST2-E07"
            case("a list of one octet more than change_list_cap_bytes: size, nothing debited, and the walk "
                 "refuses without the tree", (member, got))

    first_len, second_len = len(files[name(2)]), len(files[name(1)])
    total = first_len + second_len
    (got,) = case("a budget of exactly the octets of the chain: accepted", pull(seq[2], [seq[0]], files, total))
    assert got["chain"] == "accepted" and got["octets"] == total
    (got,) = case("a budget one octet short of the chain: suspended within the second list",
                  pull(seq[2], [seq[0]], files, total - 1))
    assert got == {"chain": "suspended", "lists_read": [seq[2]["id"]], "octets": total - 1}
    (got,) = case("a budget of exactly the first list: suspended before the second list",
                  pull(seq[2], [seq[0]], files, first_len))
    assert got == {"chain": "suspended", "lists_read": [seq[2]["id"]], "octets": first_len}
    (got,) = case("a budget one octet short of the first list: suspended within it",
                  pull(seq[2], [seq[0]], files, first_len - 1))
    assert got == {"chain": "suspended", "lists_read": [], "octets": first_len - 1}
    spaced = dict(files)
    spaced[name(1)] = files[name(1)].replace(b'"previous":', b'"previous": ', 1)
    got = case("a discarded chain whose walk refuses, then a later pull that reads the chain served then",
               pull(seq[1], [seq[0]], spaced, served_tree=False), pull(seq[1], [seq[0]], files, served_tree=False))
    assert got[0]["report"]["condition"] == "form" and got[0]["walk"]["refused"] == "WIST2-E07"
    assert got[1]["chain"] == "accepted"

    n1 = len(spaced[name(1)])
    (got,) = case("a list not of the form of more octets than the budget leaves: suspended, not form",
                  pull(seq[1], [seq[0]], spaced, n1 - 1, held_tree=seq[1]["files"]))
    assert got == {"chain": "suspended", "lists_read": [], "octets": n1 - 1}
    (got,) = case("a list not of the form of as many octets as the budget leaves: form, and the walk reads only "
                  "held tree files", pull(seq[1], [seq[0]], spaced, n1, held_tree=seq[1]["files"]))
    assert got["report"]["condition"] == "form" and got["walk"]["octets"] == 0 and "list" in got["walk"]
    free_walk = change_lists.obtain(seq[1]["catalog"], {seq[0]["id"]: lists[0]}, spaced, seq[0]["files"],
                                    seq[1]["files"])["walk"]
    walk_octets = free_walk["octets"]
    assert walk_octets == sum(len(seq[1]["files"][n]) for n in free_walk["tree_files_fetched"])
    (got,) = case("a budget of exactly the discarded chain and its walk: the walk accepts",
                  pull(seq[1], [seq[0]], spaced, n1 + walk_octets, held_tree=seq[0]["files"]))
    assert got["walk"]["octets"] == walk_octets and "list" in got["walk"]
    (got,) = case("a budget one octet short of the discarded chain and its walk: the walk reads its last file to "
                  "the bound and suspends", pull(seq[1], [seq[0]], spaced, n1 + walk_octets - 1,
                                                held_tree=seq[0]["files"]))
    assert got["walk"] == {"suspended": True, "tree_files_fetched": free_walk["tree_files_fetched"],
                           "octets": walk_octets - 1}

    file_cap = tree_files.DEFAULT_PARAMETERS["tree_file_cap_bytes"]
    wide_prefixes = [f"https://example.com/journal/wide/{i:02d}/" for i in range(16)]

    def wide_bucket(octets):
        def listed(fills):
            return items.in_list_order([removed(p + "x" * f, OBSERVED) for p, f in zip(wide_prefixes, fills)])
        fills = [1] * 16
        per, rest = divmod(octets - len(items.jcs({"items": listed(fills)})), 16)
        fills = [1 + per + (1 if i < rest else 0) for i in range(16)]
        assert len(items.jcs({"items": listed(fills)})) == octets
        return listed(fills)

    wide = wide_bucket(file_cap + 1)
    wide_tree, wide_files = tree_files.write_tree(wide, 16, file_cap=file_cap + 1)
    assert len(wide_files) == 1 and len(wide_files[wide_tree[len("sha256:"):]]) == file_cap + 1
    wide_inner = {"wist_version": "1.0.0", "publisher": "example.com", "collection": "journal",
                  "generated_at": at(1), "size": len(wide), "root": items.root_string(wide), "tree": wide_tree}
    wide_target = {"catalog": wide_inner, "id": items.catalog_id(wide_inner), "list": wide, "files": wide_files}
    (got,) = case("a discarded chain whose walk meets a root tree file one octet above tree_file_cap_bytes: the "
                  "walk refuses", pull(wide_target, [seq[0]], {}))
    assert got["walk"] == {"refused": "WIST2-E07", "tree_files_fetched": [wide_tree[len("sha256:"):]], "octets": 0}
    (got,) = case("the same walk under a map that amends tree_file_cap_bytes to the file's octets: the walk "
                  "accepts", pull(wide_target, [seq[0]], {}, parameters={"tree_file_cap_bytes": file_cap + 1}))
    assert got["walk"]["list"] == ids(wide) and got["walk"]["octets"] == file_cap + 1

    def carried(case_name, held, steps):
        aggregator = change_lists.Aggregator({s["id"]: s["list"] for s in held})
        members, outcomes = [], []
        for index, (target, served_lists, served_tree, budget) in enumerate(steps):
            got = aggregator.pull(target["catalog"], served_lists, target["files"] if served_tree else {}, budget)
            got["held_after"] = sorted(aggregator.held)
            member = {"catalog": target["catalog"], "budget": budget, "parameters": None,
                      "change_lists": {n: o.decode("utf-8") for n, o in sorted(served_lists.items())},
                      "tree_files_served": texts(target["files"]) if served_tree else {}}
            if index == 0:
                member.update(held={s["id"]: s["list"] for s in held}, held_other_collection={},
                              tree_files_held={})
            members.append(member)
            outcomes.append(got)
        cases.append({"name": case_name, "carried": True, "pulls": members, "expected": outcomes})
        return outcomes

    got = carried("a suspended chain is left: the next pull reads no change list and walks, and the pull after "
                  "it reads the chain again", [seq[0]],
                  [(seq[2], files, True, total - 1), (seq[2], files, True, None), (seq[3], files, True, None)])
    assert got[0]["chain"] == "suspended" and got[1]["chain"] == "after_suspension" and "list" in got[1]["walk"]
    assert got[2]["chain"] == "accepted" and got[2]["lists_read"] == [seq[3]["id"]]
    got = carried("a suspended chain is left and the next walk refuses: the pull after it walks again",
                  [seq[0]], [(seq[2], files, True, total - 1), (seq[2], files, False, None),
                             (seq[3], files, True, None)])
    assert got[1]["walk"]["refused"] == "WIST2-E07" and got[2]["chain"] == "after_suspension"
    assert "list" in got[2]["walk"]

    repeat_two_inner, repeat_two_files = catalog_of(lists[0], at(2, 3600))
    repeat_two = {"catalog": repeat_two_inner, "id": items.catalog_id(repeat_two_inner), "files": repeat_two_files}
    after_two_inner, after_two_tree = catalog_of(lists[1], at(3))
    after_two = {"catalog": after_two_inner, "id": items.catalog_id(after_two_inner), "files": after_two_tree}
    after_two_files = {**files, change_lists.name_of(after_two["id"]): change_lists.write(
        repeat_two["id"], lists[0], after_two["id"], lists[1])}
    got = carried("a suspended chain is left: the next pull obtains by step 1 the list of a Catalog that repeats a "
                  "held list, fetching nothing, and the pull after it reads the chain again", [seq[0]],
                  [(seq[2], files, True, total - 1), (repeat_two, files, True, None),
                   (after_two, after_two_files, True, None)])
    assert got[0]["chain"] == "suspended" and got[1]["chain"] == "held" and "walk" not in got[1]
    assert got[2]["chain"] == "accepted" and got[2]["lists_read"] == [after_two["id"]]
    assert got[2]["previous"] == repeat_two["id"]

    walked_inner, walked_files = catalog_of(lists[0], at(0))
    walked = {"catalog": walked_inner, "id": items.catalog_id(walked_inner), "files": walked_files}
    repeated_inner, repeated_files = catalog_of(lists[0], at(0, 3600))
    repeated = {"catalog": repeated_inner, "id": items.catalog_id(repeated_inner), "files": repeated_files}
    later, later_files, previous_id, previous_list = [], {}, repeated["id"], lists[0]
    for k in range(1, CHAIN_MAX + 1):
        inner, tree = catalog_of(lists[k], at(k))
        later.append({"catalog": inner, "id": items.catalog_id(inner), "files": tree})
        later_files[change_lists.name_of(later[-1]["id"])] = change_lists.write(previous_id, previous_list,
                                                                                later[-1]["id"], lists[k])
        previous_id, previous_list = later[-1]["id"], lists[k]
    got = carried("a list obtained by step 1 is held: sixteen Catalogs later the chain ends at it",
                  [], [(walked, {}, True, None), (repeated, later_files, True, None),
                       (later[-1], later_files, True, None)])
    assert got[0]["chain"] == "none" and got[1]["chain"] == "held"
    assert got[2]["chain"] == "accepted" and len(got[2]["lists_read"]) == CHAIN_MAX
    assert got[2]["previous"] == repeated["id"]

    held_payload_lists = [lst for c in cases for p in c["pulls"] for lst in
                          list(p.get("held", {}).values()) + list(p.get("held_other_collection", {}).values())]
    return {"note": (
        "ADR-0053 What an Aggregator reads, Bounds and Discarding. Each case is one or more pulls. Inputs of a "
        "pull: `catalog` is the fetched Catalog (an inner object whose fields, binding, clock and order were "
        "accepted); `held` maps the Catalog ID of each Catalog of the Publisher and the Collection whose list "
        "the Aggregator holds to that Item list; `held_other_collection` maps Catalog IDs to lists the "
        "Aggregator holds for another Collection, which no step reads; `budget` is the lesser of the remaining "
        "ingest budget and the per-pull limit (WIST-2 section 5) in octets, or null for none; `parameters` is "
        "the pull's parameter map for tree_file_cap_bytes and tree_depth_max, null for the suite values 65 536 "
        "and 16, a member it lacks taking the suite value; `change_lists` maps the name of each change list "
        "the Publisher serves (the 64 hexadecimal digits of the Catalog ID it leads to) to its octets as UTF-8 "
        "text or in compact form, a name absent from the map being a failed fetch, a list the Publisher had to "
        "stop serving included; `tree_files_held` and `tree_files_served` map tree file names to octets as "
        "vectors/wist2/catalog-tree.json has them. A case without `carried` gives every input at every pull, "
        "and each pull is read alone. A case with `carried: true` gives `held`, `held_other_collection` and "
        "`tree_files_held` at its first pull alone, the Aggregator having left no chain at a suspension "
        "before it; each later pull starts from the state the pull before left: the lists held before plus "
        "the list that pull obtained (by step 1, a chain or a walk), held under the fetched Catalog's ID; the "
        "tree files held before plus every tree file it read whole whose SHA-256 is its name; and whether it "
        "left a chain at a suspension, which lasts until a pull obtains a list. Step 1: where a held list has "
        "size Items and the root root of `catalog`, it is the list and nothing is fetched: {chain: held}. An "
        "Aggregator that left a chain at a suspension reads no change list: step 1 applies as above, and "
        "otherwise it walks instead of steps 2 to 4: {chain: after_suspension}. Step 4: with no held list, no change list is read and the tree is walked: "
        "{chain: none}. Otherwise lists are read from the one named by the fetched Catalog's ID; for each, in "
        "order: fetch (absent), size (more than 1 048 576 octets; such an answer debits nothing), then the "
        "budget (a list of as many octets as the budget leaves is read whole; one of more octets is read to "
        "that bound, those octets are debited, the list is read for no condition and the pull suspends: "
        "{chain: suspended}, no report, no walk), then form (as vectors/wist2/change-lists.json, the file named "
        "by the Catalog ID it is fetched under), then whether the list of its previous Catalog is held (which "
        "ends the reading), then chain (16 lists read); otherwise the list named by its previous Catalog is "
        "read next, one to which a list already read leads included. The lists read are applied to the held "
        "list of the last one's previous Catalog, the last read first; result is met when the outcome has "
        "another number of Items than size or another root than root. `expected` holds per pull: chain; "
        "lists_read (the Catalog IDs naming the lists read whole, in order of reading, a list failing form "
        "included); octets (the octets of the lists read whole plus, at a suspension, the octets read to the "
        "bound, a list read more than once counted at each reading; what a failed fetch debits is left open by "
        "WIST-2 section 5 and not counted); list (Item IDs in ascending octet order of key) for held and "
        "accepted and, for accepted, previous (the held Catalog ID the lists were applied to); for discarded, "
        "report {code WIST2-E08, condition, catalog: the fetched Catalog's ID, change_list: the Catalog ID "
        "naming the list at which the condition was met, the fetched Catalog's for result}; for discarded, "
        "none and after_suspension, walk; in a carried case, held_after, the Catalog IDs held after the pull "
        "in ascending order. The walk reads the tree as catalog-tree.json has it, under the pull's "
        "tree_file_cap_bytes and tree_depth_max, a held file read without fetching, any other fetched from "
        "`tree_files_served`, a name in neither being a failed fetch; it counts against the budget the chain "
        "left (budget less octets): a tree file within tree_file_cap_bytes of more octets than remain is read "
        "to that bound, debited, and the walk suspends there. walk is {list}, {refused: WIST2-E07} or "
        "{suspended: true}, with tree_files_fetched (the names requested, in ascending order, a file read to "
        "the bound and a failed fetch included) and octets (the octets of the tree files read, a file read to "
        "the bound counting the octets read; a tree file above tree_file_cap_bytes counts none, what it debits "
        "being left open by WIST-2 section 5, and no case has one under a budget). An answer above 1 048 576 "
        "octets met under a smaller budget is open in WIST-2 section 5, and no case combines them. " + LARGE_NOTE + " A compact change list's served tree is not carried, so its walk "
        "refuses. `payloads` carries the Payload of each Item of kind page that appears as an object, keyed by "
        "the digits of its Item ID; no rule here reads it."),
        "large_item_sets": LARGE, "cases": cases, "payloads": book.of(*held_payload_lists)}


write_json(WIST2 / "change-lists.json", change_list_vectors())
write_json(WIST2 / "change-list-serving.json", serving_vectors())
write_json(WIST2 / "change-chains.json", chain_vectors())
