"""Unicode helpers with first-class Greek support.

* ``fold_keep_length``: accent/case-insensitive folding that preserves string length, so regex
  offsets found on the folded text are valid on the original text.
* ``fold_greek``: full folding for use as a search/dedupe key.
* ``greek_to_latin``: ELOT 743 style transliteration (used for username/name correlation).
* ``scripts_in`` / ``is_mixed_script`` / ``confusable_skeleton``: homograph detection.
* ``decode_text``: robust bytes -> str for evidence of unknown encoding.
"""

from __future__ import annotations

import unicodedata

from .errors import InputTooLargeError

MAX_TEXT_BYTES = 32 * 1024 * 1024


# --- folding ---------------------------------------------------------------------------------


def _fold_char(ch: str) -> str:
    base = unicodedata.normalize("NFD", ch)[:1] or ch
    base = "σ" if base in ("ς", "Σ") else base
    lowered = base.lower()
    return lowered if len(lowered) == 1 else base


def fold_keep_length(text: str) -> str:
    """Lowercase, strip tonos/diaeresis and unify final sigma, one output char per input char."""
    return "".join(_fold_char(c) for c in text)


def fold_greek(text: str) -> str:
    """Full accent- and case-insensitive key (may change length)."""
    decomposed = unicodedata.normalize("NFD", text)
    stripped = "".join(c for c in decomposed if unicodedata.category(c) != "Mn")
    return unicodedata.normalize("NFC", stripped).replace("ς", "σ").casefold()


# --- ELOT 743 transliteration ----------------------------------------------------------------

_BASE = {
    "α": "a", "β": "v", "γ": "g", "δ": "d", "ε": "e", "ζ": "z", "η": "i", "θ": "th", "ι": "i",
    "κ": "k", "λ": "l", "μ": "m", "ν": "n", "ξ": "x", "ο": "o", "π": "p", "ρ": "r", "σ": "s",
    "τ": "t", "υ": "y", "φ": "f", "χ": "ch", "ψ": "ps", "ω": "o",
}
_VOICED_FOLLOW = set("αεηιοωυβγδζλμνρ")  # after au/eu: voiced -> v, otherwise f
_PLAIN_VOWELS = {"αι": "ai", "ει": "ei", "οι": "oi", "ου": "ou", "υι": "yi"}


def greek_to_latin(text: str) -> str:
    """Transliterate Greek to Latin following ELOT 743 (non-Greek characters pass through)."""
    s = fold_keep_length(text)
    caps = [c.isupper() for c in text]  # remember case by position (length preserved)
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c, nxt = s[i], (s[i + 1] if i + 1 < n else "")
        pair = c + nxt
        word_start = i == 0 or not s[i - 1].isalpha()
        piece: str
        step = 1
        if pair in ("γγ",):
            piece, step = "ng", 2
        elif pair == "γκ":
            piece, step = ("g" if word_start else "gk"), 2
        elif pair == "γξ":
            piece, step = "nx", 2
        elif pair == "γχ":
            piece, step = "nch", 2
        elif pair == "μπ":
            piece, step = ("b" if word_start else "mp"), 2
        elif pair == "ντ":
            piece, step = ("d" if word_start else "nt"), 2
        elif pair in _PLAIN_VOWELS:
            piece, step = _PLAIN_VOWELS[pair], 2
        elif pair in ("αυ", "ευ", "ηυ"):
            after = s[i + 2] if i + 2 < n else ""
            voiced = (after in _VOICED_FOLLOW) if after else True
            lead = {"α": "a", "ε": "e", "η": "i"}[c]
            piece, step = lead + ("v" if voiced else "f"), 2
        elif c in _BASE:
            piece = _BASE[c]
        else:
            piece = text[i]  # keep original character (digits, Latin, punctuation)
        if caps[i] and piece and piece[0].isalpha():
            piece = piece[0].upper() + piece[1:]
        out.append(piece)
        i += step
    return "".join(out)


# --- scripts & confusables -------------------------------------------------------------------


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return "UNKNOWN"


def scripts_in(text: str) -> set[str]:
    """Unicode script names (LATIN, GREEK, CYRILLIC, ...) of the letters in ``text``."""
    return {s for s in (_script_of(c) for c in text) if s}


def is_mixed_script(text: str) -> bool:
    return len(scripts_in(text)) > 1


# Visually confusable Greek/Cyrillic letters -> Latin look-alike (data, extendable).
_CONFUSABLES = {
    # Greek upper
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "l", "Κ": "k", "Μ": "m", "Ν": "n",
    "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
    # Greek lower
    "α": "a", "γ": "y", "ε": "e", "ι": "l", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ω": "w",
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c",
    "т": "t", "у": "y", "х": "x", "і": "l", "ј": "j", "ѕ": "s", "ԁ": "d",
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c",
    "Т": "t", "Х": "x",
    # Latin look-alikes of each other
    "i": "l", "1": "l", "|": "l", "0": "o",
}


def confusable_skeleton(text: str) -> str:
    """Map look-alike characters to a canonical ASCII skeleton for comparison (not for display)."""
    s = unicodedata.normalize("NFKC", text)
    s = "".join(_CONFUSABLES.get(c, c.lower()) for c in s)
    return s.replace("rn", "m").replace("vv", "w")


# --- decoding --------------------------------------------------------------------------------


def decode_text(data: bytes, *, limit: int = MAX_TEXT_BYTES) -> tuple[str, str, bool]:
    """Decode bytes to text. Returns ``(text, encoding, lossy)``.

    Order: BOM-based UTF-8/16/32, strict UTF-8, then UTF-8 with replacement (``lossy=True``).
    The original bytes should always be kept as the evidence; this is only for analysis.
    """
    if len(data) > limit:
        raise InputTooLargeError(size=len(data), limit=limit)
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace"), "utf-8-sig", False
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16"), "utf-16", False
        except UnicodeDecodeError:
            return data.decode("utf-16", errors="replace"), "utf-16", True
    try:
        return data.decode("utf-8"), "utf-8", False
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), "utf-8", True
