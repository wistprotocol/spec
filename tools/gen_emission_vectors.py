#!/usr/bin/env python3
import base64
import json
import pathlib

import emissions
import marked_page
from link_extraction import extract_links, extract_text

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "vectors" / "wist5"

PARAMETERS = dict(emissions.DEFAULT_PARAMETERS)

WITH_COLLECTIONS = {
    "domain": "example.com",
    "subdomain_scope": ["shop.example.com"],
    "collections": [
        {"name": "journal", "scope": [
            {"url": "https://example.com/journal/", "match": "prefix"},
            {"url": "https://example.com/", "match": "exact"}]},
        {"name": "store", "scope": [
            {"url": "https://shop.example.com/", "match": "prefix"}]},
    ],
}
IMPLICIT_DEFAULT = {"domain": "example.com", "subdomain_scope": ["blog.example.com"]}
ROOT_PREFIX = {
    "domain": "example.com",
    "collections": [
        {"name": "site", "scope": [{"url": "https://example.com/", "match": "prefix"}]},
    ],
}

MODIFIED = "2026-09-01T10:00:00Z"
LATER = "2026-09-20T08:30:00Z"


def write_json(path: pathlib.Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")


def spaced_labels(cases):
    for case in cases:
        case["label"] = case["label"].replace("-", " ")
    return cases


def line(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def header(mode, collection="journal", publisher="example.com"):
    return line({"wist_emission": "1", "publisher": publisher,
                 "collection": collection, "mode": mode})


def trailer(count):
    return line({"end": True, "count": count})


def render(lines, final_lf=True, eol="\n"):
    return eol.join(lines) + (eol if final_lf else "")


def framed(mode, body, collection="journal", publisher="example.com"):
    body = [b if isinstance(b, str) else line(b) for b in body]
    return render([header(mode, collection, publisher)] + body + [trailer(len(body))])


def emission(path, title, text=None, html=None, lang="en", modified=MODIFIED, **extra):
    out = {"url": path if path.startswith("https://") else "https://example.com" + path,
           "lang": lang, "modified": modified, "title": title}
    out.update(extra)
    if html is not None:
        out["html"] = html
    else:
        out["text"] = text
    return out


def removal(url):
    return {"url": url, "removed": True}


def publication(e, domain="example.com"):
    return emissions.derive_publication(e, domain)


def stream_field(stream):
    if isinstance(stream, bytes):
        try:
            return {"stream": stream.decode("utf-8")}
        except UnicodeDecodeError:
            return {"stream_base64": base64.b64encode(stream).decode("ascii")}
    return {"stream": stream}


def stream_case(label, stream, expect, publisher=WITH_COLLECTIONS, collection="journal",
                published=(), line_number=None):
    parameters = dict(PARAMETERS)
    octets = stream if isinstance(stream, bytes) else stream.encode("utf-8")
    result = emissions.apply_stream(octets, publisher, collection, list(published))
    if expect == "accepted":
        assert "refusal" not in result, (label, result)
    else:
        assert result.get("refusal") == expect, (label, result)
        assert result["line"] == line_number, (label, result)
    case = {"label": label, "publisher": publisher, "collection": collection,
            "parameters": parameters, "published": list(published)}
    case.update(stream_field(stream))
    case["expected"] = result
    return case


E_HOME = emission("https://example.com/", "Home", text="Welcome.")
E_A = emission("/journal/a", "First note", text="A note citing a paper.",
               links=["https://example.org/paper"])
E_B = emission("/journal/b", "Second note",
               html='<p>See <a href="https://example.net/data">the data</a>.</p>')
E_B_CHANGED = emission("/journal/b", "Second note", modified=LATER,
                       html='<p>See <a href="https://example.net/data-v2">the new data</a>.</p>')
E_C = emission("/journal/c", "Third note", text="Retired.")
E_D = emission("/journal/d", "Fourth note", text="Added later.", modified=LATER)
PUBLISHED = [publication(e) for e in (E_HOME, E_A, E_B, E_C)]


def ok_body():
    return [line(E_A)]


def application_cases():
    complete = stream_case(
        "complete-stream-reaches-publications",
        framed("complete", [E_HOME, E_A, E_B_CHANGED, E_D]), "accepted", published=PUBLISHED)
    incremental = stream_case(
        "incremental-stream-reaches-same-publications",
        framed("incremental", [E_B_CHANGED, E_D, removal("https://example.com/journal/c")]),
        "accepted", published=PUBLISHED)
    assert complete["expected"]["state"] == incremental["expected"]["state"]
    later = dict(E_A, modified=LATER)
    unchanged = stream_case(
        "later-modified-with-equal-content-is-unchanged",
        framed("incremental", [later]), "accepted", published=PUBLISHED)
    assert unchanged["expected"]["plan"]["unchanged"] == [E_A["url"]]
    lang_twin = stream_case(
        "later-modified-with-other-lang-is-changed",
        framed("incremental", [dict(later, lang="pt")]), "accepted", published=PUBLISHED)
    assert lang_twin["expected"]["plan"]["changed"] == [E_A["url"]]
    out_of_scope = publication(emission("/archive/old", "Archived", text="Old."))
    scope_left = stream_case(
        "incremental-stream-names-publication-scope-no-longer-covers",
        framed("incremental", [emission("/archive/old", "Archived", text="Newer.")]),
        "scope", published=[out_of_scope, publication(E_A)], line_number=2)
    return [scope_left,
        complete, incremental, unchanged, lang_twin,
        stream_case("removal-of-unpublished-url-has-no-effect",
                    framed("incremental", [removal("https://example.com/journal/never")]),
                    "accepted", published=PUBLISHED),
        stream_case("empty-complete-stream-removes-everything",
                    framed("complete", []), "accepted", published=PUBLISHED),
        stream_case("published-url-outside-scope-is-removed",
                    framed("incremental", [E_D]), "accepted",
                    published=[out_of_scope, publication(E_A)]),
        stream_case("crlf-line-endings-accepted",
                    render([header("complete"), line(E_A), trailer(1)], eol="\r\n"),
                    "accepted"),
        stream_case("final-lf-absent-accepted",
                    render([header("complete"), line(E_A), trailer(1)], final_lf=False),
                    "accepted"),
        stream_case("removal-outside-scope-above-url-cap-refused",
                    framed("incremental", [removal("https://example.net/" + "r" * 2100)]),
                    "cap", published=PUBLISHED, line_number=2),
        stream_case("removal-outside-scope-at-url-cap-accepted",
                    framed("incremental", [removal("https://example.net/" + "r" * (2046 - 20))]),
                    "accepted", published=PUBLISHED),
    ]


def stream_form_cases():
    good = framed("complete", [E_A])
    invalid_utf8 = good.encode("utf-8").replace(b"First note", b"First \xff note")
    lone = header("complete") + "\n" + line(E_A).replace("First note", "\\ud800") \
        + "\n" + trailer(1) + "\n"
    repeated = line(E_A)[:-1] + ',"title":"Again"}'
    return [
        stream_case("byte-order-mark", "﻿" + good, "stream-form", line_number=1),
        stream_case("invalid-utf8", invalid_utf8, "stream-form", line_number=2),
        stream_case("line-not-an-object",
                    render([header("complete"), "[1,2]", trailer(1)]), "stream-form",
                    line_number=2),
        stream_case("repeated-member-name",
                    render([header("complete"), repeated, trailer(1)]), "stream-form",
                    line_number=2),
        stream_case("lone-surrogate-escape", lone, "stream-form", line_number=2),
        stream_case("missing-header",
                    render([line(E_A), trailer(1)]), "stream-form", line_number=1),
        stream_case("header-with-extra-member",
                    render([header("complete")[:-1] + ',"extra":true}', line(E_A), trailer(1)]),
                    "stream-form", line_number=1),
        stream_case("missing-trailer",
                    render([header("complete"), line(E_A)]), "stream-form"),
        stream_case("line-after-trailer",
                    render([header("complete"), line(E_A), trailer(1), line(E_D)]),
                    "stream-form", line_number=3),
        stream_case("wrong-count",
                    render([header("complete"), line(E_A), trailer(2)]), "stream-form"),
        stream_case("count-as-decimal",
                    render([header("complete"), line(E_A), '{"end":true,"count":1.0}']),
                    "stream-form", line_number=3),
        stream_case("count-as-string",
                    render([header("complete"), line(E_A), '{"end":true,"count":"1"}']),
                    "stream-form", line_number=3),
        stream_case("count-above-safe-integer",
                    render([header("complete"), line(E_A),
                            '{"end":true,"count":9007199254740992}']),
                    "stream-form", line_number=3),
        stream_case("trailer-end-false",
                    render([header("complete"), line(E_A), '{"end":false,"count":1}']),
                    "stream-form", line_number=3),
        stream_case("zero-octets", b"", "stream-form"),
        stream_case("early-emission-form-before-later-invalid-utf8",
                    framed("complete", [dict(E_A, lang="EN"), E_D]).encode("utf-8")
                    .replace(b"Fourth note", b"Fourth \xff note"),
                    "emission-form", line_number=2),
        stream_case("leading-spaces-accepted",
                    render(["  " + header("complete"), "   " + line(E_A), " " + trailer(1)]),
                    "accepted"),
        stream_case("trailing-tab-accepted",
                    render([header("complete") + "\t", line(E_A) + "\t", trailer(1) + "\t"]),
                    "accepted"),
        stream_case("count-with-exponent",
                    render([header("complete"), line(E_A), '{"end":true,"count":1e0}']),
                    "stream-form", line_number=3),
        stream_case("count-negative-zero",
                    render([header("complete"), '{"end":true,"count":-0}']),
                    "stream-form", line_number=2),
        stream_case("count-leading-zero",
                    render([header("complete"), line(E_A), '{"end":true,"count":01}']),
                    "stream-form", line_number=3),
        stream_case("header-member-set-between-lines",
                    render([header("complete"), header("complete"), line(E_A), trailer(2)]),
                    "stream-form", line_number=2),
        stream_case("trailer-member-set-between-lines",
                    render([header("complete"), trailer(0), line(E_A), trailer(2)]),
                    "stream-form", line_number=2),
        stream_case("last-line-with-trailer-members-and-more",
                    render([header("complete"), line(E_A), '{"end":true,"count":1,"extra":1}']),
                    "emission-form", line_number=3),
        stream_case("member-object-judged-by-type",
                    framed("complete", [dict(E_A, title={"k": "v"})]),
                    "emission-form", line_number=2),
        stream_case("member-number-judged-by-type",
                    framed("complete", [dict(E_A, title=1)]),
                    "emission-form", line_number=2),
        stream_case("member-number-beyond-finite-range",
                    framed("complete", [E_A]).replace('"title":"First note"', '"title":1e999'),
                    "stream-form", line_number=2),
        stream_case("array-in-array-too-deep",
                    framed("complete", [dict(E_A, links=[["https://example.org/x"]])]),
                    "stream-form", line_number=2),
        stream_case("object-in-member-object-too-deep",
                    framed("complete", [dict(E_A, title={"k": {"a": "b"}})]),
                    "stream-form", line_number=2),
        stream_case("nested-one-hundred-thousand-deep",
                    render([header("complete"),
                            '{"url":' + "[" * 100000 + "]" * 100000 + "}", trailer(1)]),
                    "stream-form", line_number=2),
        stream_case("repeated-member-name-spelled-with-escape",
                    render([header("complete"), line(E_A)[:-1] + ',"\\u0074ext":"Again"}',
                            trailer(1)]),
                    "stream-form", line_number=2),
        stream_case("valid-emission-as-last-line-without-trailer",
                    render([header("complete"), line(E_A), line(E_D)]), "stream-form"),
        stream_case("invalid-emission-as-last-line-without-trailer",
                    render([header("complete"), line(E_A), line(dict(E_D, lang="EN"))]),
                    "emission-form", line_number=3),
        stream_case("header-member-set-as-last-line-is-emission-form",
                    render([header("complete"), line(E_A), header("complete")]),
                    "emission-form", line_number=3),
        stream_case("only-line-is-header",
                    render([header("complete")]), "stream-form"),
        stream_case("only-line-carries-trailer-members",
                    render([trailer(0)]), "stream-form", line_number=1),
        stream_case("empty-line-between-lines",
                    render([header("complete"), "", line(E_A), trailer(2)]), "stream-form",
                    line_number=2),
    ]


def header_cases():
    body = [line(E_A), trailer(1)]
    raw = {"wist_emission": "1", "publisher": "example.com",
           "collection": "journal", "mode": "complete"}
    return [
        stream_case("header-publisher-compared-by-octets",
                    framed("complete", [E_A], publisher="Example.com"), "header",
                    line_number=1),
        stream_case("collection-not-named-by-declaration",
                    framed("complete", [E_A], collection="archive"), "header",
                    collection="archive", line_number=1),
        stream_case("collection-not-named-by-declaration-without-lines",
                    framed("complete", [], collection="archive"), "header",
                    collection="archive", line_number=1),
        stream_case("collection-other-than-default-under-implicit-default",
                    framed("complete", [], collection="journal"), "header",
                    publisher=IMPLICIT_DEFAULT, collection="journal", line_number=1),
    ] + [
        stream_case("header-" + label, render([line(dict(raw, **change))] + body), "header",
                    line_number=1)
        for label, change in (
            ("version-2", {"wist_emission": "2"}),
            ("version-as-number", {"wist_emission": 1}),
            ("other-publisher", {"publisher": "example.org"}),
            ("other-collection", {"collection": "store"}),
            ("unknown-mode", {"mode": "full"}))
    ]


def emission_form_cases():
    both = dict(E_A, html="<p>x</p>")
    missing_title = {k: v for k, v in E_A.items() if k != "title"}
    links_beside_html = dict(E_B, links=["https://example.org/x"])
    cases = [
        ("unknown-member", "complete", dict(E_A, author="someone")),
        ("missing-title", "complete", missing_title),
        ("both-html-and-text", "complete", both),
        ("links-beside-html", "complete", links_beside_html),
        ("title-not-a-string", "complete", dict(E_A, title=7)),
        ("links-member-not-a-string", "complete", dict(E_A, links=["https://example.org/x", 3])),
        ("malformed-lang", "complete", dict(E_A, lang="EN")),
        ("malformed-modified-second-60", "complete", dict(E_A, modified="2016-12-31T23:59:60Z")),
        ("removal-in-complete-stream", "complete", removal("https://example.com/journal/a")),
        ("emission-with-removed-member", "incremental", dict(E_A, removed=True)),
        ("removal-with-removed-false", "incremental",
         {"url": "https://example.com/journal/a", "removed": False}),
    ]
    return [stream_case(label, framed(mode, [body]), "emission-form", line_number=2)
            for label, mode, body in cases]


def url_and_duplicate_cases():
    return [
        stream_case("url-malformed-escape",
                    framed("complete", [dict(E_A, url="https://example.com/journal/%zz")]),
                    "url", line_number=2),
        stream_case("url-not-https",
                    framed("complete", [dict(E_A, url="http://example.com/journal/a")]),
                    "url", line_number=2),
        stream_case("url-relative",
                    framed("complete", [dict(E_A, url="/journal/a")]), "url", line_number=2),
        stream_case("url-path-relative-reference",
                    framed("complete", [dict(E_A, url="/blog/a")]), "url", line_number=2),
        stream_case("url-scheme-relative-reference",
                    framed("complete", [dict(E_A, url="//example.com/a")]), "url",
                    line_number=2),
        stream_case("removal-url-without-normalized-url",
                    framed("incremental", [removal("https://example.com/journal/%g1")]),
                    "url", line_number=2),
        stream_case("duplicate-url-spelled-differently",
                    framed("complete", [E_A, dict(E_A, url="https://EXAMPLE.com/journal/./a")]),
                    "duplicate", line_number=3),
        stream_case("duplicate-emission-and-removal",
                    framed("incremental", [E_A, removal("https://example.com/journal/a#top")]),
                    "duplicate", line_number=3),
    ]


def scope_cases():
    return [
        stream_case("url-outside-every-scope",
                    framed("complete", [emission("/about", "About", text="x")]),
                    "scope", line_number=2),
        stream_case("url-inside-another-collection-scope",
                    framed("complete", [emission("https://shop.example.com/cart", "Cart",
                                                 text="x")]),
                    "scope", line_number=2),
        stream_case("host-outside-authority-under-implicit-default",
                    framed("complete", [emission("https://example.org/post", "Post", text="x")],
                           collection="default"),
                    "scope", publisher=IMPLICIT_DEFAULT, collection="default", line_number=2),
        stream_case("subdomain-scope-host-inside-implicit-default",
                    framed("complete", [emission("https://blog.example.com/post", "Post",
                                                 text="x")], collection="default"),
                    "accepted", publisher=IMPLICIT_DEFAULT, collection="default"),
        stream_case("port-on-covered-host-under-implicit-default",
                    framed("complete", [emission("https://example.com:8443/x", "Port",
                                                 text="x")], collection="default"),
                    "accepted", publisher=IMPLICIT_DEFAULT, collection="default"),
        stream_case("port-outside-root-prefix-entry",
                    framed("complete", [emission("https://example.com:8443/x", "Port",
                                                 text="x")], collection="site"),
                    "scope", publisher=ROOT_PREFIX, collection="site", line_number=2),
        stream_case("url-inside-root-prefix-entry",
                    framed("complete", [emission("https://example.com/x", "Root", text="x")],
                           collection="site"),
                    "accepted", publisher=ROOT_PREFIX, collection="site"),
        stream_case("url-inside-prefix-entry",
                    framed("complete", [emission("/journal/deep/entry?p=1", "Entry",
                                                 text="x")]),
                    "accepted"),
        stream_case("home-page-inside-exact-entry",
                    framed("complete", [E_HOME]), "accepted"),
        stream_case("url-beyond-exact-entry",
                    framed("complete", [emission("/index.html", "Index", text="x")]),
                    "scope", line_number=2),
        stream_case("url-in-other-collection-scope-read-for-store",
                    framed("complete", [emission("https://shop.example.com/cart", "Cart",
                                                 text="x")], collection="store"),
                    "accepted", collection="store"),
    ]


def _summary_abstract(target):
    abstract = "é" * ((target - emissions._jcs_length({"abstract": "", "title": "T"})) // 2)
    while emissions._jcs_length({"abstract": abstract, "title": "T"}) < target:
        abstract += "a"
    assert emissions._jcs_length({"abstract": abstract, "title": "T"}) == target
    return abstract


def _item_octets(e):
    return emissions.item_octets(publication(e), "example.com")


def _item_bound_pair(member):
    bound = emissions.items.ITEM_BOUND_OCTETS + PARAMETERS["url_cap_bytes"]
    base = emission("/journal/item", "Item", text="x")
    if member == "modified":
        fraction = "1" * (bound - _item_octets(dict(base, modified="2026-09-01T10:00:00.Z")))
        at = dict(base, modified="2026-09-01T10:00:00." + fraction + "Z")
        above = dict(base, modified="2026-09-01T10:00:00." + fraction + "1Z")
    else:
        subtags = "en"
        while bound - _item_octets(dict(base, lang=subtags)) > 16:
            subtags += "-abcdefgh"
        remaining = bound - _item_octets(dict(base, lang=subtags))
        last = min(7, remaining - 3)
        subtags += "-" + "j" * (remaining - 2 - last)
        at = dict(base, lang=subtags + "-" + "k" * last)
        above = dict(base, lang=subtags + "-" + "k" * (last + 1))
    assert _item_octets(at) == bound and _item_octets(above) == bound + 1, member
    return at, above


def cap_cases():
    base = "https://example.com/journal/"
    url_at = base + "u" * (PARAMETERS["url_cap_bytes"] - 2 - len(base))
    text_at = "x" * (PARAMETERS["extract_cap_bytes"] - 2)
    abstract_at = _summary_abstract(PARAMETERS["summary_cap_bytes"])
    pairs = [
        ("url", emission(url_at, "Long", text="x"),
         emission(url_at + "u", "Long", text="x")),
        ("extract", emission("/journal/long", "Long", text=text_at),
         emission("/journal/long", "Long", text=text_at + "x")),
        ("title-scalars", emission("/journal/t", "é" * 256, text="x"),
         emission("/journal/t", "é" * 257, text="x")),
        ("abstract-scalars", emission("/journal/s", "T", text="x", abstract="a" * 1500),
         emission("/journal/s", "T", text="x", abstract="a" * 1501)),
        ("summary-octets", emission("/journal/m", "T", text="x", abstract=abstract_at),
         emission("/journal/m", "T", text="x", abstract=abstract_at + "a")),
    ]
    dotted = base + "./" * 40
    raw_at = dotted + "u" * (PARAMETERS["url_cap_bytes"] - 2 - len(base))
    assert emissions._jcs_length(raw_at) > PARAMETERS["url_cap_bytes"]
    pairs.append(("normalized-url", emission(raw_at, "Dotted", text="x"),
                  emission(raw_at + "u", "Dotted", text="x")))
    pairs += [("item-through-modified-fraction",) + _item_bound_pair("modified"),
              ("item-through-lang-subtags",) + _item_bound_pair("lang")]
    cases = []
    for label, at_bound, above in pairs:
        cases.append(stream_case(f"cap-{label}-at-bound", framed("complete", [at_bound]),
                                 "accepted"))
        cases.append(stream_case(f"cap-{label}-above-bound", framed("complete", [above]),
                                 "cap", line_number=2))
    return cases


def precedence_cases():
    long_title = dict(E_A, title="t" * 257)
    return [
        stream_case("emission-form-before-missing-trailer",
                    render([header("complete"), line(dict(E_A, lang="EN")), line(E_D)]),
                    "emission-form", line_number=2),
        stream_case("stream-form-before-header-in-line-one",
                    render(['{"wist_emission":"1","publisher":"example.org","publisher":'
                            '"example.org","collection":"journal","mode":"complete"}',
                            line(E_A), trailer(1)]),
                    "stream-form", line_number=1),
        stream_case("stream-form-before-emission-form",
                    render([header("complete"),
                            line(dict(E_A, author="x"))[:-1] + ',"author":"y"}', trailer(1)]),
                    "stream-form", line_number=2),
        stream_case("emission-form-before-url",
                    framed("complete", [dict(E_A, url="https://example.com/%zz", author="x")]),
                    "emission-form", line_number=2),
        stream_case("emission-form-before-cap",
                    framed("complete", [dict(long_title, lang="EN")]),
                    "emission-form", line_number=2),
        stream_case("duplicate-before-scope",
                    framed("incremental", [removal("https://example.com/other/x"),
                                           emission("/other/x", "Other", text="x")]),
                    "duplicate", line_number=3),
        stream_case("duplicate-before-cap",
                    framed("complete", [E_A, long_title]), "duplicate", line_number=3),
        stream_case("scope-before-cap",
                    framed("complete", [emission("/about", "t" * 257, text="x")]),
                    "scope", line_number=2),
        stream_case("url-before-scope-and-cap",
                    framed("complete", [emission("https://example.org/%zz", "t" * 257,
                                                 text="x")]),
                    "url", line_number=2),
        stream_case("earlier-cap-before-later-stream-form",
                    render([header("complete"), line(long_title), "not json", trailer(2)]),
                    "cap", line_number=2),
        stream_case("earlier-url-before-later-emission-form",
                    framed("complete", [dict(E_A, url="https://example.com/%zz"),
                                        dict(E_D, lang="EN")]),
                    "url", line_number=2),
    ]


def derivation_case(label, e, log_parameters=None, **extra):
    parameters = dict(PARAMETERS)
    octets = framed("complete", [e], collection="default").encode("utf-8")
    result = emissions.read_stream(octets, IMPLICIT_DEFAULT, "default")
    derived = publication(e)
    assert result["publications"] == [derived], label
    case = {"label": label, "publisher": IMPLICIT_DEFAULT, "collection": "default",
            "parameters": parameters}
    if log_parameters is not None:
        case["log_parameters"] = dict(PARAMETERS, **log_parameters)
    case["emission"] = e
    case.update(extra)
    case["expected"] = derived
    return case


def derivation_cases():
    fragment = ('<p>The survey <a href="https://example.org/survey">reports</a> a rise; '
                'see <a href="/journal/method">our method</a> and '
                '<a href="https://data.example.net/set?a=1&amp;b=2">the data</a>.</p>')
    page = ('<!doctype html><html lang="en"><head><title>Rise</title></head><body>'
            '<nav><a href="https://example.net/partner">Partner</a> '
            '<a href="/about">About</a></nav><main>' + fragment + '</main>'
            '<footer><a href="https://example.org/license">License</a></footer>'
            '</body></html>')
    page_urls, page_total = extract_links(page.encode("utf-8"), "https://example.com/rise",
                                          "example.com")
    declared = [
        "//example.org/cited",
        "https://example.org/paper",
        "../journal/other",
        "https://EXAMPLE.org/paper",
        "https://example.com/about",
        "https://www.example.com/x",
        "https://example.org/%zz",
        "http://example.net/plain",
        "https://example.org/search?q=a&amp;b=c",
        "https://example.net/data#section",
    ]
    many = ["https://example.org/reference/%03d" % i for i in range(150)]
    link_at = "https://example.org/" + "k" * (PARAMETERS["link_url_cap_bytes"] - 2 - 20)
    return [
        derivation_case("html-fragment-links-exclude-surrounding-page",
                        emission("/rise", "Rise", html=fragment),
                        page=page, page_links={"total": page_total, "urls": page_urls},
                        page_extract=extract_text(page.encode("utf-8"))),
        derivation_case("text-with-declared-links",
                        emission("/notes/today", "Today",
                                 text="Fish &amp; chips\nwere cheaper\r\n  than   expected.",
                                 links=declared)),
        derivation_case("text-without-links",
                        emission("/notes/plain", "Plain", text="No links at all.")),
        derivation_case("text-with-empty-links",
                        emission("/notes/empty", "Empty", text="None.", links=[])),
        derivation_case("links-truncated-at-default-cap",
                        emission("/notes/many", "Many", text="References.", links=many)),
        derivation_case("links-read-at-default-cap-whatever-log-amended",
                        emission("/notes/many", "Many", text="References.", links=many[:10]),
                        log_parameters={"links_cap_bytes": 128}),
        derivation_case("href-with-leading-and-trailing-space-yields-bare-link",
                        emission("/notes/spaced", "Spaced",
                                 html='<a href=" https://example.org/spaced ">spaced</a>'
                                      '<a href="https://example.org/spaced">bare</a>')),
        derivation_case("declared-link-with-leading-and-trailing-space-yields-bare-link",
                        emission("/notes/spaced", "Spaced", text="Spaced.",
                                 links=[" https://example.org/spaced ", "https://example.org/spaced"])),
        derivation_case("href-with-each-ascii-whitespace-trimmed",
                        emission("/notes/whitespace", "Whitespace",
                                 html='<a href="\t\n\f\r https://example.org/ws \r\f\n\t">ws</a>')),
        derivation_case("declared-link-with-each-ascii-whitespace-trimmed",
                        emission("/notes/whitespace", "Whitespace", text="Whitespace.",
                                 links=["\t\n\f\r https://example.org/ws \r\f\n\t"])),
        derivation_case("href-beginning-with-no-break-space-not-trimmed",
                        emission("/notes/nbsp", "No-break space",
                                 html='<a href="\u00a0https://example.org/nbsp">nbsp</a>'
                                      '<a href="&#xA0;https://example.org/nbsp-ref">ref</a>')),
        derivation_case("declared-link-beginning-with-no-break-space-not-trimmed",
                        emission("/notes/nbsp", "No-break space", text="No-break space.",
                                 links=["\u00a0https://example.org/nbsp"])),
        derivation_case("extract-keeps-ideographic-no-break-and-vertical-tab-spaces",
                        emission("/notes/spaces", "Spaces",
                                 html="<p>one\u3000two\u00a0three\u000bfour \t\n five</p>")),
        derivation_case("link-above-link-url-cap-discarded-uncounted",
                        emission("/notes/long", "Long", text="Long links.",
                                 links=[link_at + "k", link_at, "https://example.net/short"])),
        derivation_case("declared-link-with-raw-space-in-path-discarded-uncounted",
                        emission("/notes/raw-space", "Raw space", text="Raw space.",
                                 links=[" https://example.org/a b ", "https://example.org/a%20b"])),
        derivation_case("declared-link-with-non-ascii-path-character-discarded-uncounted",
                        emission("/notes/non-ascii", "Non-ASCII", text="Non-ASCII.",
                                 links=["https://example.org/caf\u00e9", "https://example.org/caf%C3%A9"])),
        *(derivation_case(f"declared-link-{label}",
                          emission(f"/notes/{slug}", "Host or port", text="Host or port.", links=[link]))
          for label, slug, link in (
              ("host-with-trailing-dot-normalized-counted", "trailing-dot", "https://example.org./a"),
              ("host-with-percent-encoded-unreserved-octet-normalized-counted", "host-escape",
               "https://ex%61mple.org/x"),
              ("host-label-beginning-with-hyphen-normalized-counted", "host-hyphen", "https://-a.example.org/"),
              ("empty-port-removed-counted", "empty-port", "https://example.org:/a"),
              ("port-0443-removed-counted", "port-0443", "https://example.org:0443/a"),
              ("port-00080-written-80-counted", "port-00080", "https://example.org:00080/a"),
              ("port-above-65535-discarded-uncounted", "port-70000", "https://example.org:70000/a"))),
        derivation_case("unnormalized-url",
                        emission("https://EXAMPLE.com:443/a/./b/../c/%7e%2fx#frag", "Spelled",
                                 text="x")),
        derivation_case("abstract-present",
                        emission("/notes/abstract", "With abstract", text="Body.",
                                 abstract="A short  abstract &amp; more.")),
        derivation_case("empty-html",
                        emission("/notes/empty-html", "Empty body", html="")),
        derivation_case("empty-title",
                        emission("/notes/untitled", "", text="Untitled body.")),
        derivation_case("html-subdomain-scope-host",
                        emission("https://blog.example.com/post", "Post",
                                 html='<a href="https://blog.example.com/x">self</a>'
                                      '<a href="https://example.org/y">out</a>')),
    ]


PAGE_URL = "https://example.com/journal/marked"
MARKER = '<meta name="wist" content="publish">'
REGION = ('<!--wist:content--><h1>Marked</h1><p>Body with '
          '<a href="https://example.org/cited">a citation</a>.</p><!--/wist:content-->')


def page_of(head="<title>Marked page</title>" + MARKER, body=REGION, html_open='<html lang="en">'):
    return ('<!doctype html>' + html_open + '<head>' + head + '</head><body>'
            '<nav><a href="https://example.net/nav">nav</a></nav>' + body
            + '<footer><a href="https://example.org/footer">footer</a></footer></body></html>')


def page_case(label, page, emitted, modified=MODIFIED):
    octets = page if isinstance(page, bytes) else page.encode("utf-8")
    result = marked_page.emission_of_page(PAGE_URL, octets, modified)
    assert (result is not None) == emitted, (label, result)
    case = {"label": label, "url": PAGE_URL, "modified": modified,
            "publisher": IMPLICIT_DEFAULT, "parameters": dict(PARAMETERS)}
    if isinstance(page, bytes):
        try:
            case["page"] = page.decode("utf-8")
        except UnicodeDecodeError:
            case["page_base64"] = base64.b64encode(page).decode("ascii")
    else:
        case["page"] = page
    case["expected"] = {"emission": result,
                        "publication": None if result is None else publication(result)}
    return case


def marked_page_cases():
    title = "<title>Marked page</title>"
    return [
        page_case("marked-page", page_of(), True),
        page_case("same-page-without-marker", page_of(head=title), False),
        page_case("empty-region",
                  page_of(body="<!--wist:content--><!--/wist:content-->"), True),
        page_case("marker-inside-comment",
                  page_of(head=title + "<!--" + MARKER + "-->"), False),
        page_case("marker-inside-script",
                  page_of(head=title + "<script>var m = '" + MARKER + "';</script>"), False),
        page_case("marker-uppercase-attribute-names",
                  page_of(head=title + '<meta NAME="wist" CONTENT="publish">'), True),
        page_case("marker-attributes-in-other-order",
                  page_of(head=title + "<meta content=publish name='wist'>"), True),
        page_case("marker-content-capitalized",
                  page_of(head=title + '<meta name="wist" content="Publish">'), False),
        page_case("marker-name-capitalized-value",
                  page_of(head=title + '<meta name="WIST" content="publish">'), False),
        page_case("marker-first-name-attribute-counts",
                  page_of(head=title + '<meta name="other" name="wist" content="publish">'),
                  False),
        page_case("marker-valueless-content",
                  page_of(head=title + '<meta name="wist" content>'), False),
        page_case("delimiters-in-uppercase",
                  page_of(body="<!--WIST:CONTENT--><p>x</p><!--/WIST:CONTENT-->"), False),
        page_case("delimiters-with-inner-spaces",
                  page_of(body="<!-- wist:content --><p>x</p><!-- /wist:content -->"), False),
        page_case("delimiter-text-inside-a-start-tag-attribute",
                  page_of(body='<a title="<!--wist:content-->" href="https://example.org/">x</a>'
                               + REGION), True),
        page_case("comment-opened-inside-other-tag-hides-later-marker",
                  page_of(head="<title>Marked page</title>",
                          body=REGION + '<div title="<!--">' + MARKER).split("<footer>")[0],
                  False),
        page_case("same-page-with-closed-attribute-keeps-later-marker",
                  page_of(head="<title>Marked page</title>",
                          body=REGION + '<div title="x">' + MARKER).split("<footer>")[0],
                  True),
        page_case("valueless-description-content-gives-empty-abstract",
                  page_of(head=title + MARKER + '<meta name="description" content>'), True),
        page_case("title-end-inside-comment",
                  page_of(head="<title>A <!-- </title> --> B</title>" + MARKER), True),
        page_case("opening-delimiter-without-closing",
                  page_of(body="<!--wist:content--><p>Unclosed.</p>"), False),
        page_case("closing-delimiter-inside-script",
                  page_of(body="<!--wist:content--><p>Kept.</p>"
                               "<script>document.write('<!--/wist:content-->')</script>"
                               "<p>Also kept.</p><!--/wist:content-->"), True),
        page_case("opening-delimiter-inside-script",
                  page_of(body="<script>'<!--wist:content-->'</script><p>Outside.</p>"
                               "<!--/wist:content-->"), False),
        page_case("two-regions-first-only",
                  page_of(body="<!--wist:content--><p>First.</p><!--/wist:content-->"
                               "<!--wist:content--><p>Second.</p><!--/wist:content-->"), True),
        page_case("invalid-utf8-inside-region",
                  page_of().encode("utf-8").replace(b"Body with", b"Body \xc3( with"), True),
        page_case("region-octets-f0-80-80-give-three-replacement-characters",
                  page_of().encode("utf-8").replace(b"Body with", b"Body \xf0\x80\x80 with"), True),
        page_case("region-octets-e2-82-41-give-one-replacement-character-then-a",
                  page_of().encode("utf-8").replace(b"Body with", b"Body \xe2\x82\x41 with"), True),
        page_case("title-absent", page_of(head=MARKER), True),
        page_case("title-without-end-tag",
                  page_of(head=MARKER + "<title>Never closed"), True),
        page_case("title-surrounding-whitespace",
                  page_of(head="<title>\n   Spaced   title \t</title>" + MARKER), True),
        page_case("title-character-reference",
                  page_of(head="<title>Fish &amp; chips</title>" + MARKER), True),
        page_case("title-uppercase-tag",
                  page_of(head="<TITLE>Upper</TITLE>" + MARKER), True),
        page_case("abstract-from-description",
                  page_of(head=title + MARKER
                          + '<meta name="description" content="A page &amp; its  summary.">'),
                  True),
        page_case("description-without-content-before-one-with",
                  page_of(head=title + MARKER + '<meta name="description">'
                          + '<meta name="description" content="Second.">'),
                  True),
        page_case("lang-en", page_of(), True),
        page_case("lang-uppercase-primary-subtag",
                  page_of(html_open='<html lang="EN-us">'), True),
        page_case("lang-region-subtag-kept",
                  page_of(html_open='<html lang="pt-BR">'), True),
        page_case("lang-malformed",
                  page_of(html_open='<html lang="en_US">'), True),
        page_case("lang-absent", page_of(html_open="<html>"), True),
        page_case("lang-with-kelvin-sign-gives-und",
                  page_of(html_open='<html lang="\u212ao">'), True),
        page_case("lang-without-subtag-lowercased-whole",
                  page_of(html_open='<html lang="PT">'), True),
        page_case("lang-not-utf8",
                  page_of(html_open='<html lang="en-\xff">').encode("utf-8")
                  .replace(b"en-\xc3\xbf", b"en-\xff"), True),
    ]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    stream_cases = (application_cases() + stream_form_cases() + header_cases()
                    + emission_form_cases() + url_and_duplicate_cases() + scope_cases()
                    + cap_cases() + precedence_cases())
    write_json(OUT / "emission-streams.json", {
        "note": ("Emission streams read and applied under the Emission rules. The stream "
                 "octets are the UTF-8 encoding of stream, or the RFC 4648 base64 decoding "
                 "of stream_base64. publisher carries the Declaration members the reading "
                 "uses. published is the Collection's published state before the stream. "
                 "expected is either the refusal with the 1-based line where it is met "
                 "(null for a missing trailer, a wrong count, and a stream of zero "
                 "octets), or the resulting state and the plan, whose lists and state are "
                 "ordered by the octets of the URL."),
        "default_parameters": PARAMETERS,
        "cases": spaced_labels(stream_cases),
    })
    write_json(OUT / "emission-derivation.json", {
        "note": ("Each Emission is accepted as the only line of a complete stream for the "
                 "Collection; expected is the publication it yields under parameters, the "
                 "defaults of WIST-4 section 5; log_parameters, where present, is a map a Log "
                 "has amended, which the reading does not use. page, page_links and "
                 "page_extract show the whole page around an HTML fragment, which the "
                 "publication does not read. No case here is refused; in a refusal "
                 "elsewhere, line is the 1-based line number, null for a missing trailer and "
                 "a wrong count. Plan lists and states are ordered by the octets of the URL."),
        "default_parameters": PARAMETERS,
        "cases": spaced_labels(derivation_cases()),
    })
    write_json(OUT / "marked-pages.json", {
        "note": ("The marked-page profile. The page octets are the UTF-8 encoding of page, "
                 "or the RFC 4648 base64 decoding of page_base64. expected.emission is null "
                 "when the page is not emitted; expected.publication is the publication the "
                 "Emission yields for the publisher's domain under parameters. No case here is "
                 "refused; in a refusal elsewhere, line is the 1-based line number, null for "
                 "a missing trailer and a wrong count. Plan lists and states are ordered by "
                 "the octets of the URL."),
        "default_parameters": PARAMETERS,
        "cases": spaced_labels(marked_page_cases()),
    })
    for name in ("emission-streams", "emission-derivation", "marked-pages"):
        doc = json.loads((OUT / f"{name}.json").read_text())
        print(f"{name}.json:", len(doc["cases"]), "cases")


if __name__ == "__main__":
    main()
