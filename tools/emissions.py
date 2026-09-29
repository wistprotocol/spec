import json
import re
import urllib.parse

import rfc8785

import items
from link_extraction import _external, _iter_hrefs, extract_text, links_member, normalize_url, trim_candidate

DEFAULT_PARAMETERS = {
    "url_cap_bytes": 2048,
    "extract_cap_bytes": 32768,
    "links_cap_bytes": 4096,
    "link_url_cap_bytes": 2048,
    "summary_cap_bytes": 2048,
}

TITLE_MAX_SCALARS = 256
ABSTRACT_MAX_SCALARS = 1500
COUNT_MAX = 9007199254740991
MAX_NESTING = 2

HEADER_MEMBERS = frozenset(("wist_emission", "publisher", "collection", "mode"))
TRAILER_MEMBERS = frozenset(("end", "count"))
REMOVAL_MEMBERS = frozenset(("url", "removed"))
EMISSION_REQUIRED = frozenset(("url", "lang", "modified", "title"))

_LANG = re.compile(r"[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*")
_TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))")
_COUNT_LEXEME = re.compile(r"0|[1-9][0-9]*")
_BOM = b"\xef\xbb\xbf"
_SIZING_SALT = "A" * 22


class Refusal(Exception):
    def __init__(self, code, line):
        super().__init__(code, line)
        self.code = code
        self.line = line


class _NotALine(Exception):
    pass


class _Number:
    def __init__(self, lexeme):
        self.lexeme = lexeme


def _members(pairs):
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise _NotALine
    return dict(pairs)


def _reject_constant(_):
    raise _NotALine


def _scalar_only(node):
    if isinstance(node, str):
        return not any(0xD800 <= ord(c) <= 0xDFFF for c in node)
    if isinstance(node, dict):
        return all(_scalar_only(k) and _scalar_only(v) for k, v in node.items())
    if isinstance(node, list):
        return all(_scalar_only(v) for v in node)
    return True


def _nesting_depth(text):
    depth = deepest = 0
    in_string = escaped = False
    for c in text:
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif c in "]}":
            depth -= 1
    return deepest


def parse_line(octets):
    try:
        text = octets.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _nesting_depth(text) > MAX_NESTING:
        return None
    try:
        value = json.loads(text, object_pairs_hook=_members, parse_int=_Number,
                           parse_float=_Number, parse_constant=_reject_constant)
    except (_NotALine, ValueError):
        return None
    if not isinstance(value, dict) or not _scalar_only(value):
        return None
    return value


def split_lines(octets):
    if octets == b"":
        return []
    lines = octets.split(b"\n")
    if octets.endswith(b"\n"):
        lines.pop()
    return lines


def is_language_tag(value):
    return isinstance(value, str) and _LANG.fullmatch(value) is not None


def _leap(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def is_publisher_timestamp(value):
    if not isinstance(value, str):
        return False
    m = _TIMESTAMP.fullmatch(value)
    if m is None:
        return False
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    if not 1 <= month <= 12:
        return False
    days = [31, 29 if _leap(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if not 1 <= day <= days[month - 1]:
        return False
    if hour > 23 or minute > 59 or second > 59:
        return False
    if m.group(7) is not None and (int(m.group(7)) > 23 or int(m.group(8)) > 59):
        return False
    return True


def _jcs_length(value):
    return len(rfc8785.dumps(value))


def covers(publisher, collection, url):
    collections = publisher.get("collections")
    if collections is None:
        if collection != "default":
            return False
        host = urllib.parse.urlsplit(url).hostname
        return host == publisher["domain"] or host in publisher.get("subdomain_scope", [])
    for entry_collection in collections:
        if entry_collection["name"] != collection:
            continue
        for entry in entry_collection["scope"]:
            if entry["match"] == "exact" and url == entry["url"]:
                return True
            if entry["match"] == "prefix" and url.encode("utf-8").startswith(
                    entry["url"].encode("utf-8")):
                return True
    return False


def _surviving_links(candidates, base_url, publisher_domain, link_url_cap_bytes):
    seen, urls = set(), []
    for candidate in candidates:
        url = normalize_url(trim_candidate(candidate), base_url)
        if url is None or _jcs_length(url) > link_url_cap_bytes:
            continue
        if not _external(url, publisher_domain) or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def fragment_links(html_octets, base_url, publisher_domain, link_url_cap_bytes):
    return _surviving_links(_iter_hrefs(html_octets), base_url, publisher_domain, link_url_cap_bytes)


def declared_links(links, base_url, publisher_domain, link_url_cap_bytes):
    return _surviving_links(links, base_url, publisher_domain, link_url_cap_bytes)


def derive_content(emission, url, publisher_domain):
    parameters = DEFAULT_PARAMETERS
    if "html" in emission:
        octets = emission["html"].encode("utf-8")
        extract = extract_text(octets)
        urls = fragment_links(octets, url, publisher_domain, parameters["link_url_cap_bytes"])
    else:
        extract = emission["text"]
        urls = declared_links(emission.get("links", []), url, publisher_domain,
                              parameters["link_url_cap_bytes"])
    summary = {"title": emission["title"]}
    if "abstract" in emission:
        summary["abstract"] = emission["abstract"]
    return {"extract": extract,
            "links": links_member(urls, len(urls), parameters["links_cap_bytes"]),
            "summary": summary}


def derive_publication(emission, publisher_domain):
    url = normalize_url(emission["url"], "")
    return {"url": url, "lang": emission["lang"], "modified": emission["modified"],
            "content": derive_content(emission, url, publisher_domain)}


def _emission_form_ok(line):
    names = set(line)
    if not EMISSION_REQUIRED <= names:
        return False
    body = names - EMISSION_REQUIRED - {"abstract"}
    if body not in ({"html"}, {"text"}, {"text", "links"}):
        return False
    for name in names - {"links"}:
        if not isinstance(line[name], str):
            return False
    if "links" in line and not (isinstance(line["links"], list)
                                and all(isinstance(v, str) for v in line["links"])):
        return False
    return is_language_tag(line["lang"]) and is_publisher_timestamp(line["modified"])


def _removal_form_ok(line, mode):
    return (set(line) == REMOVAL_MEMBERS and line["removed"] is True
            and isinstance(line["url"], str) and mode == "incremental")


def item_octets(publication, publisher_domain):
    item, _ = items.new_page_item(publisher_domain, publication, _SIZING_SALT)
    return len(items.jcs(item))


def _over_cap(publication, emission, publisher_domain):
    parameters = DEFAULT_PARAMETERS
    content = publication["content"]
    return (_jcs_length(publication["url"]) > parameters["url_cap_bytes"]
            or _jcs_length(content["extract"]) > parameters["extract_cap_bytes"]
            or len(emission["title"]) > TITLE_MAX_SCALARS
            or len(emission.get("abstract", "")) > ABSTRACT_MAX_SCALARS
            or _jcs_length(content["summary"]) > parameters["summary_cap_bytes"]
            or item_octets(publication, publisher_domain) > items.ITEM_BOUND_OCTETS + parameters["url_cap_bytes"])


def names_collection(publisher, collection):
    collections = publisher.get("collections")
    if collections is None:
        return collection == "default"
    return any(c["name"] == collection for c in collections)


def _check_header(header, publisher, collection):
    if set(header) != HEADER_MEMBERS:
        raise Refusal("stream-form", 1)
    if (header["wist_emission"] != "1" or header["publisher"] != publisher["domain"]
            or header["collection"] != collection
            or not names_collection(publisher, collection)
            or header["mode"] not in ("complete", "incremental")):
        raise Refusal("header", 1)
    return header["mode"]


def _valid_trailer(trailer):
    count = trailer["count"]
    return (trailer["end"] is True and isinstance(count, _Number)
            and _COUNT_LEXEME.fullmatch(count.lexeme) is not None
            and int(count.lexeme) <= COUNT_MAX)


def read_stream(octets, publisher, collection):
    if octets.startswith(_BOM):
        raise Refusal("stream-form", 1)
    lines = split_lines(octets)
    if not lines:
        raise Refusal("stream-form", None)
    mode, trailer = None, None
    seen, publications, removals = set(), [], []
    for number, raw in enumerate(lines, 1):
        line = parse_line(raw)
        if line is None:
            raise Refusal("stream-form", number)
        if number == 1:
            mode = _check_header(line, publisher, collection)
            continue
        names = set(line)
        if names == TRAILER_MEMBERS and number == len(lines):
            if not _valid_trailer(line):
                raise Refusal("stream-form", number)
            trailer = line
            continue
        if number != len(lines) and names in (HEADER_MEMBERS, TRAILER_MEMBERS):
            raise Refusal("stream-form", number)
        is_removal = "removed" in line
        if not (_removal_form_ok(line, mode) if is_removal else _emission_form_ok(line)):
            raise Refusal("emission-form", number)
        url = normalize_url(line["url"], "")
        if url is None:
            raise Refusal("url", number)
        if url in seen:
            raise Refusal("duplicate", number)
        seen.add(url)
        if is_removal:
            if _jcs_length(url) > DEFAULT_PARAMETERS["url_cap_bytes"]:
                raise Refusal("cap", number)
            removals.append(url)
            continue
        if not covers(publisher, collection, url):
            raise Refusal("scope", number)
        publication = {"url": url, "lang": line["lang"], "modified": line["modified"],
                       "content": derive_content(line, url, publisher["domain"])}
        if _over_cap(publication, line, publisher["domain"]):
            raise Refusal("cap", number)
        publications.append(publication)
    if trailer is None or int(trailer["count"].lexeme) != len(lines) - 2:
        raise Refusal("stream-form", None)
    return {"mode": mode, "publications": publications, "removals": removals}


def _octet_order(url):
    return url.encode("utf-8")


def _same(publication, published):
    return (publication["lang"] == published["lang"]
            and rfc8785.dumps(publication["content"]) == rfc8785.dumps(published["content"]))


def apply_stream(octets, publisher, collection, published):
    try:
        stream = read_stream(octets, publisher, collection)
    except Refusal as refusal:
        return {"refusal": refusal.code, "line": refusal.line}
    current = {p["url"]: p for p in published}
    removed = [url for url, p in current.items() if not covers(publisher, collection, url)]
    for url in removed:
        del current[url]
    added, changed, unchanged = [], [], []
    result = {} if stream["mode"] == "complete" else dict(current)
    if stream["mode"] == "complete":
        removed += [url for url in current
                    if url not in {p["url"] for p in stream["publications"]}]
    for url in stream["removals"]:
        if url in result:
            del result[url]
            removed.append(url)
    for publication in stream["publications"]:
        prior = current.get(publication["url"])
        if prior is None:
            added.append(publication["url"])
            result[publication["url"]] = publication
        elif _same(publication, prior):
            unchanged.append(publication["url"])
            result[publication["url"]] = prior
        else:
            changed.append(publication["url"])
            result[publication["url"]] = publication
    return {
        "state": [result[url] for url in sorted(result, key=_octet_order)],
        "plan": {name: sorted(urls, key=_octet_order) for name, urls in (
            ("added", added), ("changed", changed),
            ("unchanged", unchanged), ("removed", removed))},
    }
