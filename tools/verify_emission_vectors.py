#!/usr/bin/env python3
import base64
import json
import pathlib
import re
import sys
from decimal import Decimal

import rfc8785

from verify_collection_vectors import normalized

ROOT = pathlib.Path(__file__).resolve().parents[1]

DEFAULT_PARAMETERS = {"url_cap_bytes": 2048, "extract_cap_bytes": 32768, "links_cap_bytes": 4096,
                      "link_url_cap_bytes": 2048, "summary_cap_bytes": 2048}
HEADER_MEMBERS = frozenset({"wist_emission", "publisher", "collection", "mode"})
TRAILER_MEMBERS = frozenset({"end", "count"})
MAX_COUNT = 9007199254740991
ITEM_BOUND_OCTETS = 16384
JSON_WS = " \t\n\r"
HTML_WS = b" \t\n\f\r"
TRIMMED = "\t\n\f\r "
TEXT_WS = re.compile(r"[\t\n\f\r ]+")
CHARACTER_REFERENCE = re.compile(r"&(?:(amp|lt|gt|quot|apos)|#([0-9]+)|#x([0-9A-Fa-f]+));")
NAMED_REFERENCES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
RAW_TEXT = (b"script", b"style", b"textarea")
TAG_OPENERS = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/!?"
ASCII_UPPER = bytes(range(0x41, 0x5B))
ASCII_LOWER = bytes(range(0x61, 0x7B))
LOWER_A_TO_Z = bytes.maketrans(ASCII_UPPER, ASCII_LOWER)

LANG = re.compile(r"[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*", re.ASCII)
LANG_BYTES = re.compile(rb"[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*")
TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?"
    r"(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))", re.ASCII)
NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", re.ASCII)
COUNT = re.compile(r"0|[1-9][0-9]*", re.ASCII)
STRING_RUN = re.compile(r'[^"\\\x00-\x1f]*')
HEX4 = re.compile(r"[0-9A-Fa-f]{4}", re.ASCII)
DOUBLE_OVERFLOW = Decimal(2**1024 - 2**970)
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
        if not m or abs(Decimal(m.group())) >= DOUBLE_OVERFLOW:
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


def decode_utf8(octets):
    # Unicode 16.0 section 3.9, Table 3-7 and U+FFFD Substitution of Maximal Subparts.
    out = []
    i, n = 0, len(octets)
    while i < n:
        lead = octets[i]
        if lead < 0x80:
            out.append(chr(lead))
            i += 1
            continue
        if 0xC2 <= lead <= 0xDF:
            ranges = [(0x80, 0xBF)]
        elif lead == 0xE0:
            ranges = [(0xA0, 0xBF), (0x80, 0xBF)]
        elif 0xE1 <= lead <= 0xEC or 0xEE <= lead <= 0xEF:
            ranges = [(0x80, 0xBF), (0x80, 0xBF)]
        elif lead == 0xED:
            ranges = [(0x80, 0x9F), (0x80, 0xBF)]
        elif lead == 0xF0:
            ranges = [(0x90, 0xBF), (0x80, 0xBF), (0x80, 0xBF)]
        elif 0xF1 <= lead <= 0xF3:
            ranges = [(0x80, 0xBF), (0x80, 0xBF), (0x80, 0xBF)]
        elif lead == 0xF4:
            ranges = [(0x80, 0x8F), (0x80, 0xBF), (0x80, 0xBF)]
        else:
            out.append("�")
            i += 1
            continue
        j = 1
        for low, high in ranges:
            if i + j < n and low <= octets[i + j] <= high:
                j += 1
            else:
                break
        if j == len(ranges) + 1:
            value = lead & (0x7F >> j)
            for k in range(1, j):
                value = (value << 6) | (octets[i + k] & 0x3F)
            out.append(chr(value))
        else:
            out.append("�")
        i += j
    return "".join(out)


def reference_value(match):
    if match.group(1):
        return NAMED_REFERENCES[match.group(1)]
    digits, base = (match.group(2), 10) if match.group(2) else (match.group(3), 16)
    digits = digits.lstrip("0") or "0"
    if len(digits) > 7:
        return None
    code = int(digits, base)
    if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
        return None
    return chr(code)


def decode_candidate(value):
    out, at = [], 0
    for match in CHARACTER_REFERENCE.finditer(value):
        decoded = reference_value(match)
        if decoded is None:
            return None
        out.append(value[at:match.start()])
        out.append(decoded)
        at = match.end()
    out.append(value[at:])
    return "".join(out)


def decode_text_references(value):
    def one(match):
        decoded = reference_value(match)
        return match.group() if decoded is None else decoded
    return CHARACTER_REFERENCE.sub(one, value)


def link_of(candidate, base, domain, params):
    url = normalized(candidate.strip(TRIMMED), base)
    return url if keep_link(url, domain, params) else None


def distinct(urls):
    seen, out = set(), []
    for url in urls:
        if url is not None and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def html_links(octets, base, domain, params):
    _, tags = scan_page(octets, (b"a",))
    found = []
    for _, attrs, _ in tags:
        href = first_attr(attrs, b"href")
        if href is None:
            continue
        candidate = decode_candidate(href.decode("utf-8"))
        if candidate is not None:
            found.append(link_of(candidate, base, domain, params))
    return distinct(found)


def declared_links(members, base, domain, params):
    return distinct(link_of(member, base, domain, params) for member in members)


def links_object(urls, cap):
    kept = 0
    while kept < len(urls) and jcs_len({"total": len(urls), "urls": urls[:kept + 1]}) <= cap:
        kept += 1
    return {"total": len(urls), "urls": urls[:kept]}


def observed_text(octets):
    low = octets.lower()
    n = len(octets)
    stripped = bytearray()
    i = 0
    while i < n:
        if octets.startswith(b"<!--", i):
            close = octets.find(b"-->", i + 4)
            stripped += b" "
            i = n if close == -1 else close + 3
            continue
        raw = next((t for t in RAW_TEXT if name_at(low, i, t)), None)
        if raw is not None:
            close = low.find(b"</" + raw, read_attributes(octets, low, i + 1 + len(raw))[1])
            stripped += b" "
            i = n if close == -1 else close
            continue
        stripped.append(octets[i])
        i += 1
    source, low, n = bytes(stripped), bytes(stripped).lower(), len(stripped)
    text = bytearray()
    i = 0
    while i < n:
        if source[i:i + 1] == b"<" and i + 1 < n and source[i + 1] in TAG_OPENERS:
            text += b" "
            i = read_attributes(source, low, i + 1)[1]
            continue
        text.append(source[i])
        i += 1
    return TEXT_WS.sub(" ", decode_text_references(decode_utf8(bytes(text)))).strip(" ")


def derive(emission, url, domain, params):
    if "html" in emission:
        octets = emission["html"].encode("utf-8")
        urls = html_links(octets, url, domain, params)
        extract = observed_text(octets)
    else:
        urls = declared_links(emission.get("links", []), url, domain, params)
        extract = emission["text"]
    summary = {"title": emission["title"]}
    if "abstract" in emission:
        summary["abstract"] = emission["abstract"]
    return {"extract": extract, "links": links_object(urls, params["links_cap_bytes"]), "summary": summary}


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
        url = normalized(obj["url"], "")
        if url is None:
            raise Refusal("url", number)
        if url in seen:
            raise Refusal("duplicate", number)
        seen.add(url)
        if "removed" in obj:
            if jcs_len(url) > params["url_cap_bytes"]:
                raise Refusal("cap", number)
            entries.append((url, None))
            continue
        if not covers(declaration, collection, url):
            raise Refusal("scope", number)
        content = derive(obj, url, domain, params)
        summary = content["summary"]
        if (jcs_len(url) > params["url_cap_bytes"]
                or jcs_len(item_of(domain, url, obj, content)) > ITEM_BOUND_OCTETS + params["url_cap_bytes"]
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


def item_of(domain, url, emission, content):
    # ADR-0052 Items and From publications to Items: a new Item of kind page; the commitment's length does not depend on the salt.
    payload = {"commitment": "hmac-sha256:" + "0" * 64, "alg": "HMAC-SHA256", "bytes": jcs_len(content)}
    return {"publisher": domain, "url": url, "observed_at": emission["modified"], "payload": payload,
            "meta": {"lang": emission["lang"]}}


def url_key(url):
    return url.encode("utf-8")


def same_publication(a, b):
    return a["lang"] == b["lang"] and rfc8785.dumps(a["content"]) == rfc8785.dumps(b["content"])


def apply_stream(octets, declaration, collection, params, published):
    try:
        mode, entries = read_stream(octets, declaration, collection, params)
    except Refusal as r:
        return {"refusal": r.name, "line": r.line}
    base = {p["url"]: p for p in published if covers(declaration, collection, p["url"])}
    added, changed, unchanged = [], [], []
    result = {} if mode == "complete" else dict(base)
    for url, pub in entries:
        if pub is None:
            result.pop(url, None)
            continue
        if url in base and same_publication(base[url], pub):
            result[url] = base[url]
            unchanged.append(url)
        else:
            (changed if url in base else added).append(url)
            result[url] = pub
    removed = [p["url"] for p in published if p["url"] not in result]
    return {
        "state": [result[u] for u in sorted(result, key=url_key)],
        "plan": {name: sorted(urls, key=url_key) for name, urls in
                 (("added", added), ("changed", changed), ("unchanged", unchanged), ("removed", removed))},
    }


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


def scan_page(page, names=(b"a", b"meta", b"title", b"html")):
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
        raw = next((t for t in RAW_TEXT if name_at(low, i, t)), None)
        if raw is not None:
            close = low.find(b"</" + raw, read_attributes(page, low, i + 1 + len(raw))[1])
            i = n if close == -1 else close
            continue
        tag = next((t for t in names if name_at(low, i, t)), None)
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
            title = observed_text(page[title_tag[2]:stop])
    lang = "und"
    html_tag = next((t for t in tags if t[0] == b"html"), None)
    if html_tag is not None:
        value = first_attr(html_tag[1], b"lang")
        if value is not None:
            dash = value.find(b"-")
            primary, rest = (value, b"") if dash == -1 else (value[:dash], value[dash:])
            value = primary.translate(LOWER_A_TO_Z) + rest
            if LANG_BYTES.fullmatch(value):
                lang = value.decode("ascii")
    emission = {"url": url, "lang": lang, "modified": modified, "title": title}
    description = next((a for a in metas if first_attr(a, b"name") == b"description"), None)
    if description is not None and first_attr(description, b"content") is not None:
        emission["abstract"] = observed_text(first_attr(description, b"content"))
    emission["html"] = decode_utf8(page[opening[1]:closing[0]])
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


class Unread(Exception):
    pass


def members_read(case, required, optional=frozenset(), one_of=()):
    keys = set(case)
    if not required <= keys:
        raise Unread(f"missing members {sorted(required - keys)}")
    for group in one_of:
        if len(keys & group) != 1:
            raise Unread(f"exactly one of {sorted(group)} expected")
    extra = keys - required - optional - set().union(*one_of)
    if extra:
        raise Unread(f"members this verifier does not read: {sorted(extra)}")


def declaration_read(declaration):
    members_read(declaration, {"domain"}, {"subdomain_scope", "collections"})
    for collection in declaration.get("collections", []):
        members_read(collection, {"name", "scope"})
        for entry in collection["scope"]:
            members_read(entry, {"url", "match"})


def default_parameters(case):
    # ADR-0050 Streams: the reading uses every parameter at its WIST-4 section 5 default.
    if case["parameters"] != DEFAULT_PARAMETERS:
        raise Unread("parameters are not the WIST-4 section 5 defaults")
    return DEFAULT_PARAMETERS


def check_streams(case):
    members_read(case, {"label", "publisher", "collection", "parameters", "published", "expected"},
                 one_of=({"stream", "stream_base64"},))
    declaration_read(case["publisher"])
    for publication in case["published"]:
        members_read(publication, {"url", "lang", "modified", "content"})
    actual = apply_stream(octets_of(case, "stream"), case["publisher"], case["collection"],
                          default_parameters(case), case["published"])
    return difference(case["expected"], actual)


def check_derivation(case):
    members_read(case, {"label", "publisher", "collection", "parameters", "emission", "expected"},
                 {"log_parameters", "page", "page_links", "page_extract"})
    declaration_read(case["publisher"])
    page_members = {"page", "page_links", "page_extract"} & set(case)
    if page_members and len(page_members) != 3:
        raise Unread("page, page_links and page_extract come together")
    if "log_parameters" in case and set(case["log_parameters"]) != set(DEFAULT_PARAMETERS):
        raise Unread("log_parameters is not a map of the five caps")
    declaration, params, emission = case["publisher"], default_parameters(case), case["emission"]
    found = difference(case["expected"], publication_of(declaration, case["collection"], emission, params))
    if found or "page" not in case:
        return found
    page = case["page"].encode("utf-8")
    url = normalized(emission["url"], "")
    links = links_object(html_links(page, url, declaration["domain"], params), params["links_cap_bytes"])
    found = difference(case["page_links"], links, "$.page_links")
    return found or difference(case["page_extract"], observed_text(page), "$.page_extract")


def check_marked(case):
    members_read(case, {"label", "publisher", "url", "modified", "parameters", "expected"},
                 one_of=({"page", "page_base64"},))
    declaration_read(case["publisher"])
    members_read(case["expected"], {"emission", "publication"})
    emission = marked_emission(octets_of(case, "page"), case["url"], case["modified"])
    found = difference(case["expected"]["emission"], emission, "$.emission")
    if found:
        return found
    publication = None if emission is None else publication_of(
        case["publisher"], "default", emission, default_parameters(case))
    return difference(case["expected"]["publication"], publication, "$.publication")


FAMILIES = (
    ("emission-streams", check_streams),
    ("emission-derivation", check_derivation),
    ("marked-pages", check_marked),
)
FILE_MEMBERS = {"cases", "default_parameters", "note"}


def main():
    directory = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "vectors" / "wist5"
    failed = False
    for family, check in FAMILIES:
        failures = []
        data = json.loads((directory / f"{family}.json").read_text("utf-8"))
        if set(data) != FILE_MEMBERS:
            failures.append(("file", f"members {sorted(set(data) ^ FILE_MEMBERS)} differ from {sorted(FILE_MEMBERS)}"))
        elif data["default_parameters"] != DEFAULT_PARAMETERS:
            failures.append(("file", "default_parameters are not the WIST-4 section 5 defaults"))
        cases = data.get("cases", [])
        for case in cases:
            try:
                found = check(case)
            except Exception as e:
                found = f"{type(e).__name__}: {e}"
            if found:
                failures.append((case.get("label"), found))
        if failures:
            failed = True
            label, found = failures[0]
            more = f" (and {len(failures) - 1} more failing cases)" if len(failures) > 1 else ""
            print(f"FAIL {family}: {len(cases)} cases: {label}: {found}{more}")
        else:
            print(f"PASS {family}: {len(cases)} cases recomputed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
