import re

from link_extraction import _at_tag_boundary, _comment_close, _raw_text_close, _raw_text_tag, extract_text
from link_extraction import first_attribute as _first
from link_extraction import read_attributes as _attributes

OPEN_DELIMITER = b"<!--wist:content-->"
CLOSE_DELIMITER = b"<!--/wist:content-->"
READ_ELEMENTS = (b"a", b"meta", b"title", b"html")

_LANG = re.compile(r"[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})*")


def scan(html):
    low = html.lower()
    n = len(html)
    i = 0
    while i < n:
        if low.startswith(b"<!--", i):
            stop = _comment_close(low, i)
            yield "comment", html[i:stop], i, stop
            i = stop
            continue
        raw_tag = _raw_text_tag(low, i)
        if raw_tag is not None:
            i = _raw_text_close(html, low, i, raw_tag)
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
