#!/usr/bin/env python3
import base64
import json
import pathlib
import re
import sys

import rfc8785

from link_extraction import extract_links, extract_text, links_member, normalize_url

ROOT = pathlib.Path(__file__).resolve().parents[1]

HEADER_MEMBERS = frozenset({"wist_emission", "publisher", "collection", "mode"})
TRAILER_MEMBERS = frozenset({"end", "count"})
MAX_COUNT = 9007199254740991
JSON_WS = " \t\n\r"
HTML_WS = b" \t\n\f\r"

LANG = re.compile(r"[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*", re.ASCII)
LANG_BYTES = re.compile(rb"[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*")
TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?"
    r"(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))", re.ASCII)
NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", re.ASCII)
COUNT = re.compile(r"0|[1-9][0-9]*", re.ASCII)
STRING_RUN = re.compile(r'[^"\\\x00-\x1f]*')
HEX4 = re.compile(r"[0-9A-Fa-f]{4}", re.ASCII)
ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


class Refusal(Exception):
    def __init__(self, name, line):
        super().__init__(name)
        self.name = name
        self.line = line


class Malformed(Exception):
    pass


class Num:
    def __init__(self, literal):
        self.literal = literal


class LineParser:
    def __init__(self, text):
        self.s = text
        self.i = 0

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] in JSON_WS:
            self.i += 1

    def parse(self):
        self.ws()
        if not self.s.startswith("{", self.i):
            raise Malformed
        value = self.value(1)
        self.ws()
        if self.i != len(self.s):
            raise Malformed
        return value

    def value(self, depth):
        if self.i >= len(self.s):
            raise Malformed
        c = self.s[self.i]
        if c in "{[":
            # ADR-0050 Streams: no array or object lies inside a member's array or object.
            if depth > 2:
                raise Malformed
            return self.obj(depth) if c == "{" else self.arr(depth)
        if c == '"':
            return self.string()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(word, self.i):
                self.i += len(word)
                return val
        m = NUMBER.match(self.s, self.i)
        if not m:
            raise Malformed
        self.i = m.end()
        return Num(m.group())

    def obj(self, depth):
        self.i += 1
        out = {}
        self.ws()
        if self.s.startswith("}", self.i):
            self.i += 1
            return out
        while True:
            self.ws()
            if not self.s.startswith('"', self.i):
                raise Malformed
            name = self.string()
            if name in out:
                raise Malformed
            self.ws()
            if not self.s.startswith(":", self.i):
                raise Malformed
            self.i += 1
            self.ws()
            out[name] = self.value(depth + 1)
            self.ws()
            if self.s.startswith(",", self.i):
                self.i += 1
                continue
            if self.s.startswith("}", self.i):
                self.i += 1
                return out
            raise Malformed

    def arr(self, depth):
        self.i += 1
        out = []
        self.ws()
        if self.s.startswith("]", self.i):
            self.i += 1
            return out
        while True:
            self.ws()
            out.append(self.value(depth + 1))
            self.ws()
            if self.s.startswith(",", self.i):
                self.i += 1
                continue
            if self.s.startswith("]", self.i):
                self.i += 1
                return out
            raise Malformed

    def hex4(self):
        m = HEX4.match(self.s, self.i)
        if not m:
            raise Malformed
        self.i = m.end()
        return int(m.group(), 16)

    def string(self):
        self.i += 1
        parts = []
        while True:
            m = STRING_RUN.match(self.s, self.i)
            parts.append(m.group())
            self.i = m.end()
            if self.i >= len(self.s):
                raise Malformed
            c = self.s[self.i]
            if c == '"':
                self.i += 1
                return "".join(parts)
            if c != "\\":
                raise Malformed
            self.i += 1
            if self.i >= len(self.s):
                raise Malformed
            e = self.s[self.i]
            self.i += 1
            if e in ESCAPES:
                parts.append(ESCAPES[e])
                continue
            if e != "u":
                raise Malformed
            cp = self.hex4()
            if 0xDC00 <= cp <= 0xDFFF:
                raise Malformed
            if 0xD800 <= cp <= 0xDBFF:
                if not self.s.startswith("\\u", self.i):
                    raise Malformed
                self.i += 2
                low = self.hex4()
                if not 0xDC00 <= low <= 0xDFFF:
                    raise Malformed
                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
            parts.append(chr(cp))


def parse_line(octets):
    try:
        text = octets.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Malformed
    return LineParser(text).parse()


def is_leap(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def valid_timestamp(value):
    m = TIMESTAMP.fullmatch(value)
    if not m:
        return False
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    if not 1 <= month <= 12:
        return False
    days = [31, 29 if is_leap(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    if not 1 <= day <= days or hour > 23 or minute > 59 or second > 59:
        return False
    if m.group(7) is not None and (int(m.group(7)) > 23 or int(m.group(8)) > 59):
        return False
    return True


def jcs_len(value):
    return len(rfc8785.dumps(value))


def host_of(url):
    authority = url[len("https://"):]
    for stop in "/?":
        cut = authority.find(stop)
        if cut != -1:
            authority = authority[:cut]
    return authority.split(":", 1)[0]


def internal(url, domain):
    host = host_of(url)
    return host == domain or host.endswith("." + domain)


def entry_covers(entry, url):
    target, own = url.encode("utf-8"), entry["url"].encode("utf-8")
    return target.startswith(own) if entry["match"] == "prefix" else target == own


def covers(declaration, collection, url):
    if "collections" not in declaration:
        return host_of(url) in {declaration["domain"], *declaration.get("subdomain_scope", [])}
    inside = outside = False
    for c in declaration["collections"]:
        hit = any(entry_covers(e, url) for e in c["scope"])
        if c["name"] == collection:
            inside = inside or hit
        else:
            outside = outside or hit
    return inside and not outside


def declared_names(declaration):
    if "collections" not in declaration:
        return {"default"}
    return {c["name"] for c in declaration["collections"]}


def keep_link(url, domain, params):
    return url is not None and jcs_len(url) <= params["link_url_cap_bytes"] and not internal(url, domain)


def derive(emission, url, domain, params):
    if "html" in emission:
        octets = emission["html"].encode("utf-8")
        found, _ = extract_links(octets, url, domain)
        urls = [u for u in found if keep_link(u, domain, params)]
        extract = extract_text(octets)
    else:
        urls, seen = [], set()
        for member in emission.get("links", []):
            u = normalize_url(member, url)
            if keep_link(u, domain, params) and u not in seen:
                seen.add(u)
                urls.append(u)
        extract = emission["text"]
    summary = {"title": emission["title"]}
    if "abstract" in emission:
        summary["abstract"] = emission["abstract"]
    links = links_member(urls, len(urls), params["links_cap_bytes"])
    return {"extract": extract, "links": links, "summary": summary}


def emission_form_ok(obj, mode):
    keys = set(obj)
    if "removed" in keys:
        return (keys == {"url", "removed"} and isinstance(obj["url"], str)
                and obj["removed"] is True and mode == "incremental")
    required = {"url", "lang", "modified", "title"}
    if not required <= keys:
        return False
    rest = keys - required - {"abstract"}
    if rest not in ({"html"}, {"text"}, {"text", "links"}):
        return False
    for name in keys - {"links"}:
        if not isinstance(obj[name], str):
            return False
    if "links" in obj and not (isinstance(obj["links"], list)
                               and all(isinstance(x, str) for x in obj["links"])):
        return False
    return LANG.fullmatch(obj["lang"]) is not None and valid_timestamp(obj["modified"])


def split_lines(octets):
    if not octets:
        return []
    lines = octets.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    return lines


def read_stream(octets, declaration, collection, params):
    if octets.startswith(b"\xef\xbb\xbf"):
        raise Refusal("stream-form", 1)
    lines = split_lines(octets)
    if not lines:
        raise Refusal("stream-form", None)
    domain = declaration["domain"]
    mode = None
    trailer = None
    seen = set()
    entries = []
    for number, octet_line in enumerate(lines, 1):
        last = number == len(lines)
        try:
            obj = parse_line(octet_line)
        except Malformed:
            raise Refusal("stream-form", number)
        keys = frozenset(obj)
        if number == 1:
            if keys != HEADER_MEMBERS:
                raise Refusal("stream-form", number)
            if (obj["wist_emission"] != "1" or not isinstance(obj["wist_emission"], str)
                    or obj["publisher"] != domain or obj["collection"] != collection
                    or collection not in declared_names(declaration)
                    or obj["mode"] not in ("complete", "incremental")):
                raise Refusal("header", number)
            mode = obj["mode"]
            continue
        if keys == TRAILER_MEMBERS:
            count = obj["count"]
            if (not last or obj["end"] is not True or not isinstance(count, Num)
                    or not COUNT.fullmatch(count.literal) or int(count.literal) > MAX_COUNT):
                raise Refusal("stream-form", number)
            trailer = int(count.literal)
            continue
        if keys == HEADER_MEMBERS and not last:
            raise Refusal("stream-form", number)
        if not emission_form_ok(obj, mode):
            raise Refusal("emission-form", number)
        url = normalize_url(obj["url"], "")
        if url is None:
            raise Refusal("url", number)
        if url in seen:
            raise Refusal("duplicate", number)
        seen.add(url)
        if "removed" in obj:
            entries.append((url, None))
            continue
        if not covers(declaration, collection, url):
            raise Refusal("scope", number)
        content = derive(obj, url, domain, params)
        summary = content["summary"]
        if (jcs_len(url) > params["url_cap_bytes"]
                or jcs_len(content["extract"]) > params["extract_cap_bytes"]
                or len(summary["title"]) > 256
                or len(summary.get("abstract", "")) > 1500
                or jcs_len(summary) > params["summary_cap_bytes"]):
            raise Refusal("cap", number)
        entries.append((url, {"url": url, "lang": obj["lang"], "modified": obj["modified"],
                              "content": content}))
    # A missing trailer and a wrong count are met after the last line.
    if trailer is None or trailer != len(lines) - 2:
        raise Refusal("stream-form", None)
    return mode, entries


def url_key(url):
    return url.encode("utf-8")


def same_publication(a, b):
    return a["lang"] == b["lang"] and rfc8785.dumps(a["content"]) == rfc8785.dumps(b["content"])


def apply_stream(octets, declaration, collection, params, published):
    try:
        mode, entries = read_stream(octets, declaration, collection, params)
    except Refusal as r:
        return {"refusal": r.name, "line": r.line}
    base, removed = {}, []
    for p in published:
        if covers(declaration, collection, p["url"]):
            base[p["url"]] = p
        else:
            removed.append(p["url"])
    added, changed, unchanged = [], [], []
    result = {} if mode == "complete" else dict(base)
    for url, pub in entries:
        if pub is None:
            if url in result:
                del result[url]
                removed.append(url)
            continue
        if url in base and same_publication(base[url], pub):
            result[url] = base[url]
            unchanged.append(url)
        else:
            (changed if url in base else added).append(url)
            result[url] = pub
    if mode == "complete":
        removed.extend(u for u in base if u not in result)
    return {
        "state": [result[u] for u in sorted(result, key=url_key)],
        "plan": {name: sorted(urls, key=url_key) for name, urls in
                 (("added", added), ("changed", changed), ("unchanged", unchanged), ("removed", removed))},
    }


def tag_end(page, j):
    n = len(page)
    while j < n:
        c = page[j:j + 1]
        if c in (b'"', b"'"):
            close = page.find(c, j + 1)
            j = n if close == -1 else close + 1
            continue
        if c == b">":
            return j
        j += 1
    return n


def name_at(low, i, name):
    k = i + 1 + len(name)
    return low.startswith(b"<" + name, i) and (k >= len(low) or low[k:k + 1] in HTML_WS + b"/>")


def read_attributes(page, low, j):
    n = len(page)
    attrs = []
    while j < n:
        c = page[j:j + 1]
        if c == b">":
            return attrs, j + 1
        if c in HTML_WS + b"/":
            j += 1
            continue
        start = j
        while j < n and page[j:j + 1] not in HTML_WS + b"=>/":
            j += 1
        name = low[start:j]
        while j < n and page[j:j + 1] in HTML_WS:
            j += 1
        value = None
        if j < n and page[j:j + 1] == b"=":
            j += 1
            while j < n and page[j:j + 1] in HTML_WS:
                j += 1
            if j < n and page[j:j + 1] in (b'"', b"'"):
                close = page.find(page[j:j + 1], j + 1)
                value, j = (page[j + 1:], n) if close == -1 else (page[j + 1:close], close + 1)
            else:
                start = j
                while j < n and page[j:j + 1] not in HTML_WS + b">":
                    j += 1
                value = page[start:j]
        attrs.append((name, b"" if value is None else value))
    return attrs, n


def first_attr(attrs, name):
    return next((v for k, v in attrs if k == name), None)


def scan_page(page):
    low = page.lower()
    n = len(page)
    comments, tags = [], []
    i = 0
    while i < n:
        if page.startswith(b"<!--", i):
            close = page.find(b"-->", i + 4)
            end = n if close == -1 else close + 3
            comments.append((i, end, page[i:end]))
            i = end
            continue
        raw = next((t for t in (b"script", b"style", b"textarea") if name_at(low, i, t)), None)
        if raw is not None:
            close = low.find(b"</" + raw, tag_end(page, i + 1 + len(raw)))
            i = n if close == -1 else close
            continue
        tag = next((t for t in (b"a", b"meta", b"title", b"html") if name_at(low, i, t)), None)
        if tag is not None:
            attrs, end = read_attributes(page, low, i + 1 + len(tag))
            tags.append((tag, attrs, end))
            i = end
            continue
        i += 1
    return comments, tags


def marked_emission(page, url, modified):
    comments, tags = scan_page(page)
    metas = [attrs for tag, attrs, _ in tags if tag == b"meta"]
    if not any(first_attr(a, b"name") == b"wist" and first_attr(a, b"content") == b"publish" for a in metas):
        return None
    opening = next((c for c in comments if c[2] == b"<!--wist:content-->"), None)
    if opening is None:
        return None
    closing = next((c for c in comments if c[0] >= opening[1] and c[2] == b"<!--/wist:content-->"), None)
    if closing is None:
        return None
    title = ""
    title_tag = next((t for t in tags if t[0] == b"title"), None)
    if title_tag is not None:
        stop = page.lower().find(b"</title", title_tag[2])
        if stop != -1:
            title = extract_text(page[title_tag[2]:stop])
    lang = "und"
    html_tag = next((t for t in tags if t[0] == b"html"), None)
    if html_tag is not None:
        value = first_attr(html_tag[1], b"lang")
        if value is not None:
            dash = value.find(b"-")
            value = value.lower() if dash == -1 else value[:dash].lower() + value[dash:]
            if LANG_BYTES.fullmatch(value):
                lang = value.decode("ascii")
    emission = {"url": url, "lang": lang, "modified": modified, "title": title}
    description = next((a for a in metas if first_attr(a, b"name") == b"description"), None)
    if description is not None and first_attr(description, b"content") is not None:
        emission["abstract"] = extract_text(first_attr(description, b"content"))
    emission["html"] = page[opening[1]:closing[0]].decode("utf-8", errors="replace")
    return emission


def single_line_stream(declaration, collection, emission):
    header = {"wist_emission": "1", "publisher": declaration["domain"],
              "collection": collection, "mode": "complete"}
    return b"\n".join([rfc8785.dumps(header), rfc8785.dumps(emission),
                       rfc8785.dumps({"end": True, "count": 1})]) + b"\n"


def publication_of(declaration, collection, emission, params):
    outcome = apply_stream(single_line_stream(declaration, collection, emission),
                           declaration, collection, params, [])
    if "refusal" in outcome:
        return outcome
    if len(outcome["state"]) != 1:
        return {"state": outcome["state"]}
    return outcome["state"][0]


def show(value):
    text = rfc8785.dumps(value).decode("utf-8") if value is not None else "null"
    return text if len(text) <= 120 else text[:117] + "..."


def difference(expected, actual, path="$"):
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in list(expected) + [k for k in actual if k not in expected]:
            if key not in expected or key not in actual:
                return f"{path}.{key}: expected {show(expected.get(key))}, got {show(actual.get(key))}"
            found = difference(expected[key], actual[key], f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(expected, list) and isinstance(actual, list):
        for k, (e, a) in enumerate(zip(expected, actual)):
            found = difference(e, a, f"{path}[{k}]")
            if found:
                return found
        if len(expected) != len(actual):
            return f"{path}: expected {len(expected)} items, got {len(actual)}"
        return None
    if type(expected) is not type(actual) or expected != actual:
        return f"{path}: expected {show(expected)}, got {show(actual)}"
    return None


def octets_of(case, key):
    if key + "_base64" in case:
        return base64.b64decode(case[key + "_base64"], validate=True)
    return case[key].encode("utf-8")


def check_streams(case):
    actual = apply_stream(octets_of(case, "stream"), case["publisher"], case["collection"],
                          case["parameters"], case["published"])
    return difference(case["expected"], actual)


def check_derivation(case):
    declaration, params, emission = case["publisher"], case["parameters"], case["emission"]
    found = difference(case["expected"], publication_of(declaration, case["collection"], emission, params))
    if found or "page" not in case:
        return found
    page = case["page"].encode("utf-8")
    domain = declaration["domain"]
    url = normalize_url(emission["url"], "")
    urls = [u for u in extract_links(page, url, domain)[0] if keep_link(u, domain, params)]
    found = difference(case["page_links"], links_member(urls, len(urls), params["links_cap_bytes"]), "$.page_links")
    return found or difference(case["page_extract"], extract_text(page), "$.page_extract")


def check_marked(case):
    emission = marked_emission(octets_of(case, "page"), case["url"], case["modified"])
    found = difference(case["expected"]["emission"], emission, "$.emission")
    if found:
        return found
    publication = None if emission is None else publication_of(
        case["publisher"], "default", emission, case["parameters"])
    return difference(case["expected"]["publication"], publication, "$.publication")


FAMILIES = (
    ("emission-streams", check_streams),
    ("emission-derivation", check_derivation),
    ("marked-pages", check_marked),
)


def main():
    directory = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "vectors" / "wist5"
    failed = False
    for family, check in FAMILIES:
        failures = []
        for case in json.loads((directory / f"{family}.json").read_text("utf-8"))["cases"]:
            try:
                found = check(case)
            except Exception as e:
                found = f"{type(e).__name__}: {e}"
            if found:
                failures.append((case["label"], found))
        if failures:
            failed = True
            label, found = failures[0]
            more = f" (and {len(failures) - 1} more failing cases)" if len(failures) > 1 else ""
            print(f"FAIL {family}: {label}: {found}{more}")
        else:
            print(f"PASS {family}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
