"""Email addresses and @handles."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..errors import ValidationError
from .urls import normalize_host, refang

_FILE_EXTS = frozenset({"png", "jpg", "jpeg", "gif", "webp", "svg", "css", "js", "json", "txt", "pdf", "html",
                        "htm", "php", "py", "md", "zip", "mp4", "mov", "ico", "bmp", "tiff", "heic"})
_GOOGLE = frozenset({"gmail.com", "googlemail.com"})

_EMAIL_RE = re.compile(
    r"(?<![\w.+\-@])[\w.+\-]{1,64}(?:@|\[at\]|\(at\)|\[@\])"
    r"[^\W_](?:[\w\-]{0,61}[^\W_])?(?:(?:\.|\[\.\]|\(\.\))[^\W_](?:[\w\-]{0,61}[^\W_])?)+",
    re.I | re.U,
)


@dataclass(frozen=True)
class EmailInfo:
    address: str  # lower-cased local@domain (ASCII/punycode domain)
    local: str
    domain: str
    alias_key: str | None  # Google-specific dot/plus normalisation (heuristic), else None


def parse_email(raw: str) -> EmailInfo:
    s = refang(raw.strip())
    if s.count("@") != 1:
        raise ValidationError(f"not an email: {raw!r}")
    local, domain = s.split("@")
    if not local or len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
        raise ValidationError(f"invalid local part: {raw!r}")
    host, _, kind = normalize_host(domain)
    if kind != "domain" or "." not in host:
        raise ValidationError(f"invalid email domain: {raw!r}")
    tld = host.rsplit(".", 1)[1]
    if tld in _FILE_EXTS or tld.isdigit():
        raise ValidationError(f"looks like a file name, not an email: {raw!r}")
    local = local.lower()
    alias = None
    if host in _GOOGLE:
        alias = local.split("+", 1)[0].replace(".", "") + "@gmail.com"
    return EmailInfo(f"{local}@{host}", local, host, alias)


def find_emails(text: str) -> list[tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group(0)) for m in _EMAIL_RE.finditer(text)]


# --- handles ---------------------------------------------------------------------------------

_MENTION_RE = re.compile(r"(?<![\w.@/])@([A-Za-z0-9_](?:[A-Za-z0-9_.]{0,28}[A-Za-z0-9_])?)(?![\w@])")
_KEYWORD_RE = re.compile(
    r"\b(?:insta(?:gram)?|ig|inst)\b[ \t]*(?:[:\-–=][ \t]*@?|@)([A-Za-z0-9_](?:[A-Za-z0-9_.]{1,28}[A-Za-z0-9_]))\b", re.I
)
_STOP = frozenset({"instagram", "insta", "ig", "inst", "me", "you", "the", "and", "for", "gmail", "yahoo"})


def find_handles(text: str) -> list[tuple[int, int, str, str]]:
    """``(start, end, raw, platform)``: ``instagram`` if a keyword names it, else ``unknown``."""
    found: list[tuple[int, int, str, str]] = []
    for m in _KEYWORD_RE.finditer(text):
        handle = m.group(1)
        if handle.lower() in _STOP or handle.isdigit():
            continue
        found.append((m.start(1), m.end(1), handle, "instagram"))
    for m in _MENTION_RE.finditer(text):
        handle = m.group(1)
        if handle.lower() in _STOP or handle.isdigit():
            continue
        found.append((m.start(), m.end(), "@" + handle, "unknown"))
    return found
