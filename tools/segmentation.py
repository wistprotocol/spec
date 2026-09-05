"""UAX #29 default word boundaries and extended grapheme clusters.

WIST-4 §5 segments both texts by the *default* word-boundary rules, with
no dictionary-based or language-specific tailoring, and counts extended
grapheme clusters on its short-text branch. Both are implemented here from
the annex rather than taken from a library, for the reason `ecvrf.py` gives
for the VRF: this is the procedure that decides a verdict, and a
conformance reference that borrowed it would be checking a dependency
rather than the text. `tools/gen_unicode_tables.py` supplies the property
ranges, from the one Unicode release ADR-0017 pins.

The implementation is checked against the Unicode Consortium's own
`WordBreakTest.txt` and `GraphemeBreakTest.txt` for that release; see
`tools/VERIFICATION.md`.
"""
from bisect import bisect_right

from unicode_tables import (
    EXTENDED_PICTOGRAPHIC,
    EXTENDED_PICTOGRAPHIC_VALUES,
    GRAPHEME_BREAK,
    GRAPHEME_BREAK_VALUES,
    INCB,
    INCB_VALUES,
    UNICODE_VERSION,
    WORD_BREAK,
    WORD_BREAK_VALUES,
)

__all__ = ["UNICODE_VERSION", "split_word_bounds", "grapheme_clusters"]


def _lookup(table, values, cp, default):
    i = bisect_right(table, (cp, 0x10FFFF + 1, len(values))) - 1
    if i >= 0 and table[i][0] <= cp <= table[i][1]:
        return values[table[i][2]]
    return default


def _wb(cp):
    return _lookup(WORD_BREAK, WORD_BREAK_VALUES, cp, "Other")


def _gb(cp):
    return _lookup(GRAPHEME_BREAK, GRAPHEME_BREAK_VALUES, cp, "Other")


def _incb(cp):
    return _lookup(INCB, INCB_VALUES, cp, "None")


def _extpict(cp):
    return _lookup(EXTENDED_PICTOGRAPHIC, EXTENDED_PICTOGRAPHIC_VALUES, cp, None) \
        == "Extended_Pictographic"


# ------------------------------------------------------------------ words

_NEWLINES = {"Newline", "CR", "LF"}
_IGNORE = {"Extend", "Format", "ZWJ"}
_AHLETTER = {"ALetter", "Hebrew_Letter"}
_MIDNUMLETQ = {"MidNumLet", "Single_Quote"}


def split_word_bounds(text):
    """UAX #29 default word boundaries: every segment of `text`, in order,
    with nothing dropped — the caller applies §5's L*/N* filter."""
    cps = [ord(c) for c in text]
    n = len(cps)
    if n == 0:
        return []
    wb = [_wb(cp) for cp in cps]

    # WB4: X (Extend | Format | ZWJ)* -> X, where X is not CR, LF or
    # Newline. An ignorable with no such X before it is its own X.
    absorbed = [False] * n
    for i in range(n):
        if wb[i] not in _IGNORE or i == 0:
            continue
        j = i - 1
        while j >= 0 and absorbed[j]:
            j -= 1
        if j >= 0 and wb[j] not in _NEWLINES:
            absorbed[i] = True

    def before(i):
        """The index the rules after WB4 read as preceding boundary `i`."""
        j = i - 1
        while j >= 0 and absorbed[j]:
            j -= 1
        return j

    def after(i):
        """The index the rules after WB4 read as following position `i`."""
        j = i + 1
        while j < n and absorbed[j]:
            j += 1
        return j if j < n else None

    def ri_run_before(i):
        """WB15/WB16: how many Regional_Indicators precede boundary `i`."""
        count = 0
        j = before(i)
        while j is not None and j >= 0 and wb[j] == "Regional_Indicator":
            count += 1
            j = before(j)
        return count

    breaks = [0]
    for i in range(1, n):
        a_lit, b_lit = wb[i - 1], wb[i]
        if a_lit == "CR" and b_lit == "LF":          # WB3
            continue
        if a_lit in _NEWLINES:                       # WB3a
            breaks.append(i)
            continue
        if b_lit in _NEWLINES:                       # WB3b
            breaks.append(i)
            continue
        if a_lit == "ZWJ" and _extpict(cps[i]):      # WB3c
            continue
        if a_lit == "WSegSpace" and b_lit == "WSegSpace":   # WB3d
            continue
        if b_lit in _IGNORE and absorbed[i]:         # WB4
            continue

        j = before(i)
        A = wb[j] if j >= 0 else None
        B = b_lit
        nxt = after(i)
        N = wb[nxt] if nxt is not None else None
        prev2 = before(j) if j >= 0 else -1
        P = wb[prev2] if prev2 is not None and prev2 >= 0 else None

        if A in _AHLETTER and B in _AHLETTER:                       # WB5
            continue
        if A in _AHLETTER and (B == "MidLetter" or B in _MIDNUMLETQ) \
                and N in _AHLETTER:                                 # WB6
            continue
        if (A == "MidLetter" or A in _MIDNUMLETQ) and B in _AHLETTER \
                and P in _AHLETTER:                                 # WB7
            continue
        if A == "Hebrew_Letter" and B == "Single_Quote":            # WB7a
            continue
        if A == "Hebrew_Letter" and B == "Double_Quote" \
                and N == "Hebrew_Letter":                           # WB7b
            continue
        if A == "Double_Quote" and B == "Hebrew_Letter" \
                and P == "Hebrew_Letter":                           # WB7c
            continue
        if A == "Numeric" and B == "Numeric":                       # WB8
            continue
        if A in _AHLETTER and B == "Numeric":                       # WB9
            continue
        if A == "Numeric" and B in _AHLETTER:                       # WB10
            continue
        if (A == "MidNum" or A in _MIDNUMLETQ) and B == "Numeric" \
                and P == "Numeric":                                 # WB11
            continue
        if A == "Numeric" and (B == "MidNum" or B in _MIDNUMLETQ) \
                and N == "Numeric":                                 # WB12
            continue
        if A == "Katakana" and B == "Katakana":                     # WB13
            continue
        if A in _AHLETTER | {"Numeric", "Katakana", "ExtendNumLet"} \
                and B == "ExtendNumLet":                            # WB13a
            continue
        if A == "ExtendNumLet" and B in _AHLETTER | {"Numeric", "Katakana"}:
            continue                                                # WB13b
        if A == "Regional_Indicator" and B == "Regional_Indicator" \
                and ri_run_before(i) % 2 == 1:                      # WB15/WB16
            continue
        breaks.append(i)                                            # WB999

    breaks.append(n)
    return [text[breaks[k]:breaks[k + 1]] for k in range(len(breaks) - 1)]


# -------------------------------------------------------------- graphemes

def grapheme_clusters(text):
    """UAX #29 extended grapheme clusters, in order."""
    cps = [ord(c) for c in text]
    n = len(cps)
    if n == 0:
        return []
    gb = [_gb(cp) for cp in cps]

    breaks = [0]
    for i in range(1, n):
        a, b = gb[i - 1], gb[i]
        if a == "CR" and b == "LF":                                 # GB3
            continue
        if a in {"Control", "CR", "LF"}:                            # GB4
            breaks.append(i)
            continue
        if b in {"Control", "CR", "LF"}:                            # GB5
            breaks.append(i)
            continue
        if a == "L" and b in {"L", "V", "LV", "LVT"}:               # GB6
            continue
        if a in {"LV", "V"} and b in {"V", "T"}:                    # GB7
            continue
        if a in {"LVT", "T"} and b == "T":                          # GB8
            continue
        if b in {"Extend", "ZWJ"}:                                  # GB9
            continue
        if b == "SpacingMark":                                      # GB9a
            continue
        if a == "Prepend":                                          # GB9b
            continue
        if _incb(cps[i]) == "Consonant" and _incb_linked(cps, i):   # GB9c
            continue
        if b is not None and _extpict(cps[i]) and _pictographic_zwj(cps, gb, i):
            continue                                                # GB11
        if a == "Regional_Indicator" and b == "Regional_Indicator" \
                and _ri_run(gb, i) % 2 == 1:                        # GB12/GB13
            continue
        breaks.append(i)                                            # GB999

    breaks.append(n)
    return [text[breaks[k]:breaks[k + 1]] for k in range(len(breaks) - 1)]


def _incb_linked(cps, i):
    """GB9c: an InCB=Linker, preceded only by InCB=Extend or Linker, back to
    an InCB=Consonant."""
    seen_linker = False
    j = i - 1
    while j >= 0:
        value = _incb(cps[j])
        if value == "Linker":
            seen_linker = True
        elif value == "Extend":
            pass
        elif value == "Consonant":
            return seen_linker
        else:
            return False
        j -= 1
    return False


def _pictographic_zwj(cps, gb, i):
    """GB11: \\p{Extended_Pictographic} Extend* ZWJ x \\p{Extended_Pictographic}."""
    if gb[i - 1] != "ZWJ":
        return False
    j = i - 2
    while j >= 0 and gb[j] == "Extend":
        j -= 1
    return j >= 0 and _extpict(cps[j])


def _ri_run(gb, i):
    count = 0
    j = i - 1
    while j >= 0 and gb[j] == "Regional_Indicator":
        count += 1
        j -= 1
    return count
