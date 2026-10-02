"""Reference link extraction (WIST-2 §11) and link agreement (WIST-4 §5).

Test-suite implementation: operates on raw HTML octets, never a DOM, so
JavaScript-inserted links do not exist for it. Deterministic by
construction. Fixture hosts are ASCII and already canonical; the UTS #46
Canonical Host step of WIST-1 §2 is therefore a lowercasing here, and a
fixture MUST NOT carry a host that UTS #46 and lowercasing disagree on.

`normalize_url` is reject-not-repair (WIST-1 §2): a malformed escape, a
control octet, userinfo in the authority, or a host outside the lowercase
LDH grammar all discard the candidate rather than attempt to salvage it,
and any exception raised while parsing does the same — a hostile or
merely malformed href MUST NOT abort extraction of the rest of the page.
"""
import re
import urllib.parse

import rfc8785

_UNRESERVED_TEXT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
_UNRESERVED = set(_UNRESERVED_TEXT.encode("ascii"))

_SUB_DELIMS = "!$&'()*+,;="
_REG_NAME_CHARACTERS = frozenset(_UNRESERVED_TEXT + _SUB_DELIMS + "%")
_URI_CHARACTERS = frozenset(_UNRESERVED_TEXT + _SUB_DELIMS + ":/?#[]@%")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_BROKEN_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")

_HOST_LDH = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)*\Z")

_CHAR_REF = re.compile(
    r"&(amp|lt|gt|quot|apos);|&#(\d+);|&#x([0-9A-Fa-f]+);", re.ASCII)
_NAMED_REFS = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}

_RAWTEXT_TAGS = (b"script", b"style", b"textarea")

ASCII_WHITESPACE = "\t\n\f\r "
_ASCII_WHITESPACE_RUN = re.compile("[\t\n\f\r ]+")


def trim_candidate(candidate: str) -> str:
    return candidate.strip(ASCII_WHITESPACE)


def _decode_entities(s: str):
    """WIST-2 §11 step 4: decode the five named references and numeric
    character references (decimal and hex). An `&` that forms none of
    these is left exactly as written.

    The `re.ASCII` flag on `_CHAR_REF` scopes exactly one group, the
    decimal run: `\\d` on a `str` pattern otherwise matches every Unicode
    decimal digit, and Python's `int()` normalizes those before
    conversion, so `&#٦٥;` would silently decode to `A` against the
    ASCII-digit repertoire WIST-2 §11 step 4 pins. The hex run needs no
    such scoping and never did — it is written as the explicit ASCII
    class `[0-9A-Fa-f]`.

    A numeric reference whose code point is not a Unicode scalar value —
    above 0x10FFFF, or a surrogate 0xD800-0xDFFF — makes the whole
    candidate not a link: returns None, the same fail-closed posture WIST-1
    §2 takes toward an unresolvable escape. Discarding here, at the
    candidate, is what keeps a poison reference from surfacing later as
    an uncaught `ValueError` (`chr()` rejects > 0x10FFFF) or a `str` that
    `rfc8785.dumps` cannot encode (a lone surrogate) — a crash or a
    silent bad emission, not merely a skip.

    The digit run is length-bounded *before* `int()` ever sees it, rather
    than relying on catching whatever an interpreter's own bignum-parsing
    limit raises: 0x10FFFF is 7 decimal digits / 6 hex digits, so a
    significant (leading-zeros-stripped) run longer than that cannot
    denote a scalar value either way, and is discarded without a
    conversion attempt at all — deterministic and interpreter-independent,
    not a size an int() call ever has to survive.
    """
    invalid = False

    def repl(m):
        nonlocal invalid
        if m.group(1) is not None:
            return _NAMED_REFS[m.group(1)]
        digits, base = (m.group(2), 10) if m.group(2) is not None else (m.group(3), 16)
        max_digits = 7 if base == 10 else 6
        significant = digits.lstrip("0") or "0"
        if len(significant) > max_digits:
            invalid = True
            return ""
        try:
            cp = int(significant, base)
        except ValueError:
            invalid = True
            return ""
        if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
            invalid = True
            return ""
        return chr(cp)

    out = _CHAR_REF.sub(repl, s)
    return None if invalid else out


def _at_tag_boundary(low: bytes, pos: int) -> bool:
    return pos >= len(low) or low[pos:pos + 1] in (b" ", b"\t", b"\n", b"\f", b"\r", b"/", b">")


_WHITESPACE = (b" ", b"\t", b"\n", b"\f", b"\r")


def read_attributes(html: bytes, low: bytes, j: int):
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
                end_q = html.find(html[j:j + 1], j + 1)
                value, j = (html[j + 1:], n) if end_q == -1 else (html[j + 1:end_q], end_q + 1)
            else:
                value_start = j
                while j < n and html[j:j + 1] not in _WHITESPACE + (b">",):
                    j += 1
                value = html[value_start:j]
        attributes.append((name, value))
    return attributes, n


def first_attribute(attributes, name: bytes):
    return next((value for attr, value in attributes if attr == name), None)


def _raw_text_tag(low: bytes, i: int):
    return next((t for t in _RAWTEXT_TAGS
                 if low.startswith(b"<" + t, i) and _at_tag_boundary(low, i + 1 + len(t))), None)


def _raw_text_close(html: bytes, low: bytes, i: int, tag: bytes) -> int:
    _, start_tag_end = read_attributes(html, low, i + 1 + len(tag))
    close = low.find(b"</" + tag, start_tag_end)
    return len(html) if close == -1 else close


def _comment_close(low: bytes, i: int) -> int:
    end = low.find(b"-->", i + 4)
    return len(low) if end == -1 else end + 3


def _iter_hrefs(html: bytes):
    low = html.lower()
    n = len(html)
    i = 0
    while i < n:
        if low.startswith(b"<!--", i):
            i = _comment_close(low, i)
            continue
        raw_tag = _raw_text_tag(low, i)
        if raw_tag is not None:
            i = _raw_text_close(html, low, i, raw_tag)
            continue
        if low.startswith(b"<a", i) and _at_tag_boundary(low, i + 2):
            attributes, i = read_attributes(html, low, i + 2)
            href = first_attribute(attributes, b"href")
            if href is None:
                continue
            try:
                candidate = href.decode("utf-8")
            except UnicodeDecodeError:
                continue
            decoded = _decode_entities(candidate)
            if decoded is not None:
                yield decoded
            continue
        i += 1


def _renormalize_escapes(s: str):
    """RFC 3986 §6.2.2: uppercase escape hex; decode unreserved octets.
    Returns None on a malformed escape (no Normalized URL exists)."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "%":
            if not re.match(r"%[0-9A-Fa-f]{2}", s[i:i + 3]):
                return None
            octet = int(s[i + 1:i + 3], 16)
            if octet in _UNRESERVED:
                out.append(chr(octet))
            else:
                out.append("%" + s[i + 1:i + 3].upper())
            i += 3
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _host_span(candidate: str):
    scheme = _SCHEME.match(candidate)
    start = scheme.end() if scheme else 0
    if not scheme and ":" in re.split(r"[/?#]", candidate, maxsplit=1)[0]:
        return False
    if not candidate.startswith("//", start):
        return None
    start += 2
    end = start
    while end < len(candidate) and candidate[end] not in "/?#":
        end += 1
    if "@" in candidate[start:end]:
        return False
    if candidate.startswith("[", start):
        close = candidate.find("]", start, end)
        return (start, end if close == -1 else close + 1)
    colon = candidate.find(":", start, end)
    return (start, end if colon == -1 else colon)


def _uri_form(candidate: str) -> bool:
    span = _host_span(candidate)
    if span is False:
        return False
    if span is None:
        host, outside = "", candidate
    else:
        host, outside = candidate[span[0]:span[1]], candidate[:span[0]] + candidate[span[1]:]
    if any(c not in _URI_CHARACTERS or c in "[]" for c in outside):
        return False
    if outside.count("#") > 1 or _BROKEN_ESCAPE.search(outside):
        return False
    if host.startswith("["):
        return host.endswith("]") and all(c in _URI_CHARACTERS for c in host)
    return all(not c.isascii() or c in _REG_NAME_CHARACTERS for c in host)


def _canonical_ascii_host(host: str):
    host = _renormalize_escapes(host)
    if host is None:
        return None
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if len(host) > 253 or not _HOST_LDH.match(host):
        return None
    if any(len(label) > 63 for label in host.split(".")):
        return None
    return host


def normalize_url(candidate: str, base_url: str):
    """WIST-1 §2 Normalized URL, or None. Query escapes are renormalized but
    the query is never parsed or reordered.

    Reject-not-repair: a character RFC 3986 does not allow outside the host
    (a raw space, a control or a non-ASCII character among them), a userinfo
    (`@`) in the resolved authority, or a host that is not lowercase LDH
    all return None, as does any exception the parse steps raise — a
    hostile or malformed href discards the link rather than aborting the
    scan or guessing at a repair.
    """
    if not _uri_form(candidate):
        return None
    try:
        resolved = urllib.parse.urljoin(base_url, candidate)
        parts = urllib.parse.urlsplit(resolved)
        if parts.scheme != "https":
            return None
        if "@" in parts.netloc:
            return None       # userinfo: reject, do not strip and continue
        host = _canonical_ascii_host(parts.hostname or "")
        if host is None:
            return None
        if parts.port not in (None, 443):
            netloc = f"{host}:{parts.port}"
        else:
            netloc = host
        path = _renormalize_escapes(parts.path)
        if path is None:
            return None
        path = _remove_dot_segments(path) or "/"
        query = None
        if parts.query != "" or "?" in resolved.split("#")[0]:
            query = _renormalize_escapes(parts.query)
            if query is None:
                return None
        out = f"https://{netloc}{path}"
        if query is not None:
            out += "?" + query
        return out
    except Exception:
        return None


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4, exactly: a trailing `.` or `..` segment emits a
    trailing `/`, so `/a/b/..` normalizes to `/a/` (not `/a`) and an
    absolute and a relative spelling of the same target agree."""
    output = []
    while path:
        if path.startswith("../"):
            path = path[3:]
        elif path.startswith("./"):
            path = path[2:]
        elif path.startswith("/./"):
            path = "/" + path[3:]
        elif path == "/.":
            path = "/"
        elif path.startswith("/../"):
            path = "/" + path[4:]
            if output:
                output.pop()
        elif path == "/..":
            path = "/"
            if output:
                output.pop()
        elif path in (".", ".."):
            path = ""
        else:
            start = 1 if path.startswith("/") else 0
            idx = path.find("/", start)
            if idx == -1:
                output.append(path)
                path = ""
            else:
                output.append(path[:idx])
                path = path[idx:]
    return "".join(output)


def _external(url: str, publisher_domain: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    return host != publisher_domain and not host.endswith("." + publisher_domain)


LINK_URL_CAP_BYTES = 2048


def extract_links(html: bytes, base_url: str, publisher_domain: str,
                  link_url_cap_bytes: int = LINK_URL_CAP_BYTES):
    """WIST-2 §11's procedure: hrefs of <a> in octet order -> resolve ->
    normalize (drop failures) -> external only -> dedup first-wins.
    Returns (urls, total)."""
    seen, urls = set(), []
    for candidate in _iter_hrefs(html):
        url = normalize_url(trim_candidate(candidate), base_url)
        if url is None or len(rfc8785.dumps(url)) > link_url_cap_bytes:
            continue
        if not _external(url, publisher_domain) or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls, len(urls)


def links_member(urls, total, cap_bytes: int) -> dict:
    for k in range(len(urls), -1, -1):
        member = {"total": total, "urls": urls[:k]}
        if len(rfc8785.dumps(member)) <= cap_bytes:
            return member
    raise AssertionError(
        f"cap_bytes={cap_bytes} is below the minimal links object "
        f'{{"total": {total}, "urls": []}}; no conforming member exists')


def _decode_text_entities(s: str) -> str:
    def repl(m):
        if m.group(1) is not None:
            return _NAMED_REFS[m.group(1)]
        digits, base = (m.group(2), 10) if m.group(2) is not None else (m.group(3), 16)
        significant = digits.lstrip("0") or "0"
        if len(significant) > (7 if base == 10 else 6):
            return m.group(0)
        cp = int(significant, base)
        if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
            return m.group(0)
        return chr(cp)
    return _CHAR_REF.sub(repl, s)


def _without_comments_and_raw_text(html: bytes) -> bytes:
    low = html.lower()
    n = len(html)
    out = bytearray()
    i = 0
    while i < n:
        if low.startswith(b"<!--", i):
            i = _comment_close(low, i)
            out += b" "
            continue
        raw_tag = _raw_text_tag(low, i)
        if raw_tag is not None:
            i = _raw_text_close(html, low, i, raw_tag)
            out += b" "
            continue
        out.append(html[i])
        i += 1
    return bytes(out)


_TAG_OPENERS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/!?")


def extract_text(html: bytes) -> str:
    source = _without_comments_and_raw_text(html)
    low = source.lower()
    n = len(source)
    out = bytearray()
    i = 0
    while i < n:
        if source[i] == 0x3C and i + 1 < n and source[i + 1] in _TAG_OPENERS:
            _, i = read_attributes(source, low, i + 1)
            out += b" "
            continue
        out.append(source[i])
        i += 1
    # Python's "replace" handler substitutes one U+FFFD per maximal subpart
    # (Unicode 16.0 §3.9), as WIST-2 §12 step 3 requires.
    text = bytes(out).decode("utf-8", errors="replace")
    text = _decode_text_entities(text)
    return _ASCII_WHITESPACE_RUN.sub(" ", text).strip(" ")
