import re

from link_extraction import _RAWTEXT_TAGS, _at_tag_boundary, _tag_end, extract_text

OPEN_DELIMITER = b"<!--wist:content-->"
CLOSE_DELIMITER = b"<!--/wist:content-->"
READ_ELEMENTS = (b"a", b"meta", b"title", b"html")

_WHITESPACE = (b" ", b"\t", b"\n", b"\f", b"\r")
_LANG = re.compile(r"[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*")


def _attributes(html, low, j):
    n = len(html)
    attributes = []
    while j < n:
        c = html[j:j + 1]
        if c == b">":
            return attributes, j + 1
        if c in _WHITESPACE or c == b"/":
            j += 1
            continue
        name_start = j
        while j < n and html[j:j + 1] not in _WHITESPACE + (b"=", b">", b"/"):
            j += 1
        name = low[name_start:j]
        while j < n and html[j:j + 1] in _WHITESPACE:
            j += 1
        value = b""
        if j < n and html[j:j + 1] == b"=":
            j += 1
            while j < n and html[j:j + 1] in _WHITESPACE:
                j += 1
            if j < n and html[j:j + 1] in (b'"', b"'"):
                quote = html[j:j + 1]
                end_q = html.find(quote, j + 1)
                value, j = (html[j + 1:], n) if end_q == -1 else (html[j + 1:end_q], end_q + 1)
            else:
                value_start = j
                while j < n and html[j:j + 1] not in _WHITESPACE + (b">",):
                    j += 1
                value = html[value_start:j]
        attributes.append((name, value))
    return attributes, n


def _first(attributes, name):
    return next((value for attr, value in attributes if attr == name), None)


def scan(html):
    low = html.lower()
    n = len(html)
    i = 0
    while i < n:
        if low.startswith(b"<!--", i):
            end = low.find(b"-->", i + 4)
            stop = n if end == -1 else end + 3
            yield "comment", html[i:stop], i, stop
            i = stop
            continue
        raw_tag = next((t for t in _RAWTEXT_TAGS
                        if low.startswith(b"<" + t, i)
                        and _at_tag_boundary(low, i + 1 + len(t))), None)
        if raw_tag is not None:
            open_end = _tag_end(html, i + 1 + len(raw_tag))
            close = low.find(b"</" + raw_tag, open_end)
            i = n if close == -1 else close
            continue
        element = next((t for t in READ_ELEMENTS
                        if low.startswith(b"<" + t, i)
                        and _at_tag_boundary(low, i + 1 + len(t))), None)
        if element is not None:
            attributes, j = _attributes(html, low, i + 1 + len(element))
            yield element, attributes, i, j
            i = j
            continue
        i += 1


def _language(value):
    if value is None:
        return "und"
    dash = value.find(b"-")
    tag = value.lower() if dash == -1 else value[:dash].lower() + value[dash:]
    try:
        text = tag.decode("utf-8")
    except UnicodeDecodeError:
        return "und"
    return text if _LANG.fullmatch(text) else "und"


def emission_of_page(url, page, modified):
    marked = False
    region_start = region = None
    title_start = None
    description = html_lang = None
    seen_description = seen_html = False
    for kind, detail, start, end in scan(page):
        if kind == "comment":
            if region_start is None and detail == OPEN_DELIMITER:
                region_start = end
            elif region_start is not None and region is None and detail == CLOSE_DELIMITER:
                region = page[region_start:start]
            continue
        name = _first(detail, b"name")
        if kind == b"meta":
            if name == b"wist" and _first(detail, b"content") == b"publish":
                marked = True
            if name == b"description" and not seen_description:
                seen_description = True
                description = _first(detail, b"content")
        elif kind == b"title" and title_start is None:
            title_start = end
        elif kind == b"html" and not seen_html:
            seen_html = True
            html_lang = _first(detail, b"lang")
    if not marked or region is None:
        return None
    title = ""
    if title_start is not None:
        close = page.lower().find(b"</title", title_start)
        if close != -1:
            title = extract_text(page[title_start:close])
    emission = {"url": url, "lang": _language(html_lang), "modified": modified, "title": title}
    if description is not None:
        emission["abstract"] = extract_text(description)
    emission["html"] = region.decode("utf-8", errors="replace")
    return emission
