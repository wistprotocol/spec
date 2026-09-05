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

_UNRESERVED = set(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

_HOST_LDH = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")

_CHAR_REF = re.compile(
    r"&(amp|lt|gt|quot|apos);|&#(\d+);|&#[xX]([0-9A-Fa-f]+);", re.ASCII)
_NAMED_REFS = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}

_RAWTEXT_TAGS = (b"script", b"style", b"textarea")


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
    """True if `pos` is at whitespace, `/`, `>`, or past the end — the set
    of octets WIST-2 §11 step 3 allows right after a tag name."""
    return pos >= len(low) or low[pos:pos + 1] in (b" ", b"\t", b"\n", b"\f", b"\r", b"/", b">")


def _tag_end(html: bytes, pos: int) -> int:
    """Index of the first unquoted `>` at/after `pos`, or len(html) if none.
    Quote-aware, so a `>` inside a quoted attribute value does not end the
    tag — used to find where a raw-text element's start tag closes."""
    n = len(html)
    j = pos
    while j < n:
        c = html[j:j + 1]
        if c in (b'"', b"'"):
            end_q = html.find(c, j + 1)
            j = n if end_q == -1 else end_q + 1
            continue
        if c == b">":
            return j
        j += 1
    return n


def _iter_hrefs(html: bytes):
    """WIST-2 §11 steps 1-4: yield each `<a>` element's `href` value, in
    document order, with character references already decoded.

    Comments and raw-text element content (script/style/textarea) are
    skipped whole, never scanned for `<a>` or nested comments. Attribute
    parsing is quote-aware, so a `>` inside a quoted value cannot
    truncate the tag, and only the first attribute named exactly `href`
    counts — `data-href` is a different attribute. An element whose
    `href` carries a non-scalar-value numeric character reference is
    silently skipped (`_decode_entities` returning None) rather than
    yielded or allowed to abort the scan.
    """
    low = html.lower()
    n = len(html)
    i = 0
    while i < n:
        if low.startswith(b"<!--", i):
            end = low.find(b"-->", i + 4)
            i = n if end == -1 else end + 3
            continue

        raw_tag = next((t for t in _RAWTEXT_TAGS
                        if low.startswith(b"<" + t, i)
                        and _at_tag_boundary(low, i + 1 + len(t))), None)
        if raw_tag is not None:
            open_end = _tag_end(html, i + 1 + len(raw_tag))
            close = low.find(b"</" + raw_tag, open_end)
            i = n if close == -1 else close
            continue

        if low.startswith(b"<a", i) and _at_tag_boundary(low, i + 2):
            j = i + 2
            href_value = None
            while j < n:
                c = html[j:j + 1]
                if c == b">":
                    j += 1
                    break
                if c in (b" ", b"\t", b"\n", b"\f", b"\r", b"/"):
                    j += 1
                    continue
                name_start = j
                while j < n and html[j:j + 1] not in (
                        b" ", b"\t", b"\n", b"\f", b"\r", b"=", b">", b"/"):
                    j += 1
                name = low[name_start:j]
                while j < n and html[j:j + 1] in (b" ", b"\t", b"\n", b"\f", b"\r"):
                    j += 1
                value = None
                if j < n and html[j:j + 1] == b"=":
                    j += 1
                    while j < n and html[j:j + 1] in (b" ", b"\t", b"\n", b"\f", b"\r"):
                        j += 1
                    if j < n and html[j:j + 1] in (b'"', b"'"):
                        quote = html[j:j + 1]
                        j += 1
                        val_start = j
                        end_q = html.find(quote, j)
                        if end_q == -1:
                            value, j = html[val_start:n], n
                        else:
                            value, j = html[val_start:end_q], end_q + 1
                    else:
                        val_start = j
                        while j < n and html[j:j + 1] not in (
                                b" ", b"\t", b"\n", b"\f", b"\r", b">"):
                            j += 1
                        value = html[val_start:j]
                if name == b"href" and href_value is None:
                    href_value = value if value is not None else b""
            if href_value is not None:
                decoded = _decode_entities(href_value.decode("utf-8", errors="replace"))
                if decoded is not None:
                    yield decoded
                # else: a non-scalar-value numeric reference — this <a>
                # element's href is discarded (per-candidate, WIST-2 §11
                # step 4), never a reason to abort the rest of the scan.
            i = j
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


def normalize_url(candidate: str, base_url: str):
    """WIST-1 §2 Normalized URL, or None. Query escapes are renormalized but
    the query is never parsed or reordered.

    Reject-not-repair: a raw control octet in the candidate, a userinfo
    (`@`) in the resolved authority, or a host that is not lowercase LDH
    all return None, as does any exception the parse steps raise — a
    hostile or malformed href discards the link rather than aborting the
    scan or guessing at a repair.
    """
    if any(ord(c) < 0x20 for c in candidate):
        return None          # urlsplit silently drops a raw tab/CR/LF
    try:
        resolved = urllib.parse.urljoin(base_url, candidate)
        parts = urllib.parse.urlsplit(resolved)
        if parts.scheme != "https":
            return None
        if "@" in parts.netloc:
            return None       # userinfo: reject, do not strip and continue
        host = (parts.hostname or "").lower()
        if not _HOST_LDH.match(host):
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


def extract_links(html: bytes, base_url: str, publisher_domain: str):
    """WIST-2 §11's procedure: hrefs of <a> in octet order -> resolve ->
    normalize (drop failures) -> external only -> dedup first-wins.
    Returns (urls, total)."""
    seen, urls = set(), []
    for candidate in _iter_hrefs(html):
        url = normalize_url(candidate.strip(), base_url)
        if url is None or not _external(url, publisher_domain) or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls, len(urls)


def links_member(urls, total, cap_bytes: int) -> dict:
    """The longest prefix whose serialized links object fits cap_bytes.

    `links` is REQUIRED (WIST-3 §6.1) and `links_cap_bytes` MUST be at
    least the 21 octets of `{"total":0,"urls":[]}` (WIST-4 §9), so a
    cap_bytes below that admits no conforming member at all — a bug in
    the caller, not a case to paper over by returning something over cap.
    """
    for k in range(len(urls), -1, -1):
        member = {"total": total, "urls": urls[:k]}
        if len(rfc8785.dumps(member)) <= cap_bytes:
            return member
    raise AssertionError(
        f"cap_bytes={cap_bytes} is below the minimal links object "
        f'{{"total": {total}, "urls": []}}; no conforming member exists')


def link_agreement(declared_urls, declared_total, observed_urls, observed_total):
    """WIST-4 §5: min(subset Jaccard, count agreement), integer micro-units."""
    d, o = set(declared_urls), set(observed_urls)
    union = d | o
    subset = 1_000_000 if not union else (len(d & o) * 1_000_000) // len(union)
    hi = max(declared_total, observed_total)
    count = 1_000_000 if hi == 0 else (min(declared_total, observed_total) * 1_000_000) // hi
    return min(subset, count)


# --------------------------------------------- WIST-2 §12: text extraction

def _decode_text_entities(s: str) -> str:
    """WIST-2 §12 step 3: the §11 step-4 repertoire, salvage-free.

    Text is not a link candidate: there is nothing to discard fail-closed.
    A reference that is malformed, over-long, or names a non-scalar code
    point is left exactly as written — deterministic either way, and never
    an exception.
    """
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


def extract_text(html: bytes) -> str:
    """WIST-2 §12: whole-document text extraction over raw HTML octets.

    Comments, raw-text element content (script/style/textarea) and tags
    each contribute a single space; a `<` that opens none of these is
    literal text. Octets decode as UTF-8 with U+FFFD replacement — the
    declared charset is never consulted, so two Auditors cannot disagree
    via charset sniffing. Character references decode per §11's pinned
    repertoire; ASCII whitespace runs collapse to single spaces.
    """
    low = html.lower()
    n = len(html)
    out = []
    i = 0
    while i < n:
        if low.startswith(b"<!--", i):
            end = low.find(b"-->", i + 4)
            i = n if end == -1 else end + 3
            out.append(b" ")
            continue
        raw_tag = next((t for t in _RAWTEXT_TAGS
                        if low.startswith(b"<" + t, i)
                        and _at_tag_boundary(low, i + 1 + len(t))), None)
        if raw_tag is not None:
            start_end = _tag_end(html, i)
            close = low.find(b"</" + raw_tag, start_end)
            i = n if close == -1 else _tag_end(html, close) + 1
            out.append(b" ")
            continue
        c = html[i:i + 1]
        if c == b"<" and i + 1 < n and (
                chr(low[i + 1]).isascii() and chr(low[i + 1]).isalpha()
                or html[i + 1:i + 2] in (b"/", b"!", b"?")):
            i = _tag_end(html, i) + 1
            out.append(b" ")
            continue
        nxt = html.find(b"<", i + 1) if c == b"<" else html.find(b"<", i)
        if nxt == -1:
            nxt = n
        out.append(html[i:nxt])
        i = nxt
    text = b"".join(out).decode("utf-8", errors="replace")
    text = _decode_text_entities(text)
    return " ".join(text.split())


# ----------------------- WIST-4 §5: similarity (reference containment)

def _shingles(units, n):
    return {tuple(units[k:k + n]) for k in range(len(units) - n + 1)}


def similarity(reference: str, observed: str, min_observed_words: int = 40,
               shingle_size: int = 8):
    """WIST-4 §5: reference-containment similarity, integer micro-units.

    Returns None where the mass guard rules the audit `not_auditable`:
    an observed text below `min_observed_words` is a page that says
    almost nothing, and absence is not contradiction. Otherwise
    floor(|A ∩ B| × 1e6 / |A|) over `shingle_size`-word shingles, falling
    to grapheme shingles of length min(shingle_size, g_A, g_B) when
    either text has fewer than `shingle_size` words. One parameter
    governs both the length and the branch threshold (§5).

    Test-suite scope: normalization here is NFC + str.casefold(), and
    word segmentation is whitespace splitting; fixtures are restricted
    to the ASCII letters-and-spaces domain, on which these coincide
    exactly with WIST-4 §5's default full case folding and untailored
    UAX #29 rules. A fixture outside that domain is a fixture bug.
    """
    import unicodedata
    ref = unicodedata.normalize("NFC", reference).casefold()
    obs = unicodedata.normalize("NFC", observed).casefold()
    ref_words, obs_words = ref.split(), obs.split()
    if len(obs_words) < min_observed_words:
        return None
    if len(ref_words) >= shingle_size and len(obs_words) >= shingle_size:
        a = _shingles(ref_words, shingle_size)
        b = _shingles(obs_words, shingle_size)
    else:
        n = min(shingle_size, len(ref), len(obs))
        a = _shingles(list(ref), n)
        b = _shingles(list(obs), n)
    assert a, "empty reference reaches similarity(); WIST-4 §5 rules it not_auditable earlier"
    return (len(a & b) * 1_000_000) // len(a)
