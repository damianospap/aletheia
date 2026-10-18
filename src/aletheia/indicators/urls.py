"""URL and domain indicators.

Handles the things real scam material does to links: defanging (``hxxp://evil[.]com``), tracking
parameters, redirect shims (``l.instagram.com/?u=``), user-info tricks (``paypal.com@evil.com``),
and internationalised look-alike domains. Nothing here performs any network access.
"""

from __future__ import annotations

import html
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..errors import ValidationError
from ..textnorm import is_mixed_script

TRACKING_PARAMS = frozenset(
    {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id", "fbclid", "gclid",
     "igshid", "igsh", "mc_cid", "mc_eid", "ref_src", "_ga"}
)
_MULTI_SUFFIX = frozenset(
    {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.gr", "gov.gr", "edu.gr", "org.gr", "net.gr", "com.au", "com.br",
     "com.tr", "co.in", "co.za", "com.cn", "com.ua", "co.jp", "com.mx", "com.sg", "com.hk"}
)
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}

# Conservative TLD list for *bare* domain detection (file-like extensions such as .py/.sh/.zip omitted).
BARE_TLDS = frozenset(
    "com net org info biz io co me xyz top online site shop store club live vip app dev link click gr eu uk de fr "
    "it es nl be ch at pt ie fi se no dk pl cz sk hu ro bg hr si rs ua ru by lt lv ee cy mt tr us ca au nz jp cn in "
    "br mx ar cl za ng ke eg ae sa il tk ml ga cf gq cc ws pw icu cyou buzz work support help today world life ltd "
    "cloud tech page website space fun lol win bid loan trade date party stream download review science cam mobi "
    "name pro asia agency finance capital cash money bank pay exchange market global network systems solutions "
    "services center group company email chat tv one wiki".split()
)

_REFANG = (
    (re.compile(r"h(?:xx|tt)p(s?)(?::|\[:\]|\(:\))//", re.I), r"http\1://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.I), "@"),
)


def refang(text: str) -> str:
    """Undo common defanging so indicators can be handled uniformly."""
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


# --- hosts -----------------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


def normalize_host(host: str) -> tuple[str, str, str]:
    """Return ``(ascii_host, unicode_host, kind)`` where kind is ``'ip'`` or ``'domain'``."""
    h = host.strip().rstrip(".")
    try:
        ip = ipaddress.ip_address(h)
        return str(ip), str(ip), "ip"
    except ValueError:
        pass
    h = unicodedata.normalize("NFC", h).lower()
    labels = h.split(".")
    if not h or any(not label for label in labels):
        raise ValidationError(key="error.validation.domain", value=host)
    ascii_labels: list[str] = []
    uni_labels: list[str] = []
    for label in labels:
        try:
            if label.startswith("xn--"):
                uni_labels.append(label[4:].encode("ascii").decode("punycode"))
                ascii_labels.append(label)
            elif label.isascii():
                ascii_labels.append(label)
                uni_labels.append(label)
            else:
                ascii_labels.append("xn--" + label.encode("punycode").decode("ascii"))
                uni_labels.append(label)
        except UnicodeError as exc:
            raise ValidationError(key="error.validation.domain", value=host) from exc
    if any(not _LABEL_RE.match(label) for label in ascii_labels) or len(".".join(ascii_labels)) > 253:
        raise ValidationError(key="error.validation.domain", value=host)
    return ".".join(ascii_labels), ".".join(uni_labels), "domain"


def host_mixed_script(host_unicode: str) -> bool:
    """True if any single DNS label mixes alphabets (a Greek label under ``.gr`` is fine)."""
    return any(is_mixed_script(label) for label in host_unicode.split("."))


def registrable_domain(host_ascii: str) -> str:
    """Approximate registrable domain (eTLD+1) using a small built-in multi-part suffix list."""
    labels = host_ascii.split(".")
    if len(labels) <= 2:
        return host_ascii
    if ".".join(labels[-2:]) in _MULTI_SUFFIX:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# --- URLs ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class UrlInfo:
    canonical: str
    scheme: str
    host: str  # ASCII / punycode
    host_unicode: str
    port: int | None
    path: str
    query: str
    host_kind: str  # 'domain' | 'ip'
    is_idn: bool
    mixed_script: bool
    has_userinfo: bool
    registrable: str
    unwrapped: "UrlInfo | None" = None


def _shim_target(host: str, path: str, pairs: list[tuple[str, str]]) -> str | None:
    if host == "l.instagram.com" and path in ("", "/"):
        keys: tuple[str, ...] = ("u",)
    elif host in ("l.facebook.com", "lm.facebook.com") and path == "/l.php":
        keys = ("u",)
    elif host in ("www.google.com", "google.com") and path == "/url":
        keys = ("q", "url")
    else:
        return None
    for key, value in pairs:
        if key in keys and value.lower().startswith(("http://", "https://")):
            return value
    return None


def parse_url(raw: str, *, _depth: int = 0) -> UrlInfo:
    """Parse and canonicalise an absolute URL. Raises ``ValidationError`` when unusable."""
    s = html.unescape(refang(raw.strip()))
    if "://" not in s:
        raise ValidationError(key="error.validation.url", url=raw)
    try:
        parts = urlsplit(s)
        port = parts.port
    except ValueError as exc:
        raise ValidationError(key="error.validation.url", url=raw) from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValidationError(key="error.validation.scheme", url=raw)
    if not parts.hostname:
        raise ValidationError(key="error.validation.url", url=raw)
    host, host_uni, kind = normalize_host(parts.hostname)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    kept = sorted((k, v) for k, v in pairs if k.lower() not in TRACKING_PARAMS)
    netloc = f"[{host}]" if kind == "ip" and ":" in host else host
    if port and port != _DEFAULT_PORTS[scheme]:
        netloc += f":{port}"
    path = parts.path or "/"
    canonical = urlunsplit((scheme, netloc, path, urlencode(kept), ""))
    unwrapped = None
    target = _shim_target(host, parts.path, pairs)
    if target and _depth < 3:
        try:
            unwrapped = parse_url(target, _depth=_depth + 1)
        except ValidationError:
            unwrapped = None
    is_idn = any(label.startswith("xn--") for label in host.split(".")) if kind == "domain" else False
    return UrlInfo(
        canonical=canonical,
        scheme=scheme,
        host=host,
        host_unicode=host_uni,
        port=port,
        path=path,
        query=urlencode(kept),
        host_kind=kind,
        is_idn=is_idn,
        mixed_script=host_mixed_script(host_uni) if kind == "domain" else False,
        has_userinfo="@" in parts.netloc,
        registrable=registrable_domain(host) if kind == "domain" else host,
        unwrapped=unwrapped,
    )


# --- discovery in free text ------------------------------------------------------------------

_URL_RE = re.compile(
    r"(?<![\w@])(?:h(?:tt|xx)ps?|ftp)(?:://|\[:\]//|\(:\)//)[^\s<>\"'`\u200b\u3000]+", re.I
)
_TRAIL = ".,;:!?'\"»”’…"
_CLOSERS = {")": "(", "]": "[", "}": "{", ">": "<"}


def _trim_url(s: str) -> str:
    while s:
        last = s[-1]
        if last in _TRAIL:
            s = s[:-1]
            continue
        opener = _CLOSERS.get(last)
        if opener and s.count(last) > s.count(opener):
            s = s[:-1]
            continue
        break
    return s


def find_urls(text: str) -> list[tuple[int, int, str]]:
    """Return ``(start, end, raw)`` for scheme-prefixed (possibly defanged) URLs."""
    found = []
    for m in _URL_RE.finditer(text):
        raw = _trim_url(m.group(0))
        if len(raw) > 8:
            found.append((m.start(), m.start() + len(raw), raw))
    return found


_LABEL = r"[^\W_](?:[\w-]{0,61}[^\W_])?"
_BARE_RE = re.compile(
    rf"(?<![\w@./\-])((?:{_LABEL}(?:\[\.\]|\(\.\)|\.))+)([^\W\d_]{{2,24}})(?![\w\-@])", re.U
)
_FILE_LIKE_TLDS = frozenset({"py", "sh", "md", "js", "rs", "pl", "zip", "mov", "txt", "png", "jpg", "gif", "css", "php"})


def find_bare_domains(text: str) -> list[tuple[int, int, str, bool]]:
    """Domains without a scheme. Returns ``(start, end, raw, defanged)``.

    Plain domains are accepted only with a known TLD; defanged ones (``evil[.]top``) with any TLD.
    """
    found = []
    for m in _BARE_RE.finditer(text):
        raw = m.group(0)
        defanged = "[.]" in raw or "(.)" in raw
        tld = m.group(2).lower()
        if tld in _FILE_LIKE_TLDS:
            continue
        if not defanged and tld not in BARE_TLDS:
            continue
        found.append((m.start(), m.end(), raw, defanged))
    return found


# --- Instagram & other social URLs -----------------------------------------------------------

_IG_HOSTS = frozenset({"instagram.com", "www.instagram.com", "m.instagram.com", "instagr.am", "www.instagr.am"})
_IG_RESERVED = frozenset(
    "explore accounts p reel reels stories tv direct about legal developer web challenge emails api graphql oauth "
    "privacy press directory locations session static nametag lite shop _u".split()
)
_HANDLE_RE = re.compile(r"^[A-Za-z0-9._]{1,30}$")
_SHORTCODE_RE = re.compile(r"^[A-Za-z0-9_-]{5,64}$")


@dataclass(frozen=True)
class IgRef:
    kind: str  # profile | post | reel | tv | story | highlight | tag | home | other
    handle: str | None = None
    shortcode: str | None = None
    ident: str | None = None


def classify_instagram(info: UrlInfo) -> IgRef | None:
    """Describe what an Instagram URL points at (``None`` if it is not an Instagram URL)."""
    if info.host == "ig.me":
        segs = [s for s in info.path.split("/") if s]
        if len(segs) >= 2 and segs[0] == "m" and _HANDLE_RE.match(segs[1]):
            return IgRef("profile", handle=segs[1].lower())
        return None
    if info.host not in _IG_HOSTS:
        return None
    segs = [s for s in info.path.split("/") if s]
    if not segs:
        return IgRef("home")
    first = segs[0].lower()
    if first in ("p", "reel", "reels", "tv") and len(segs) >= 2 and _SHORTCODE_RE.match(segs[1]):
        kind = {"p": "post", "reel": "reel", "reels": "reel", "tv": "tv"}[first]
        return IgRef(kind, shortcode=segs[1])
    if first == "stories" and len(segs) >= 2:
        if segs[1] == "highlights" and len(segs) >= 3:
            return IgRef("highlight", ident=segs[2])
        handle = segs[1].lower() if _HANDLE_RE.match(segs[1]) else None
        return IgRef("story", handle=handle, ident=segs[2] if len(segs) > 2 else None)
    if first == "explore":
        if len(segs) >= 3 and segs[1] == "tags":
            return IgRef("tag", ident=segs[2])
        return IgRef("other")
    if first == "_u" and len(segs) >= 2 and _HANDLE_RE.match(segs[1]):
        return IgRef("profile", handle=segs[1].lower())
    if first in _IG_RESERVED:
        return IgRef("other")
    if _HANDLE_RE.match(segs[0]):
        if len(segs) >= 3 and segs[1].lower() in ("p", "reel") and _SHORTCODE_RE.match(segs[2]):
            return IgRef("post" if segs[1].lower() == "p" else "reel", handle=segs[0].lower(), shortcode=segs[2])
        return IgRef("profile", handle=segs[0].lower())
    return None


@dataclass(frozen=True)
class SocialRef:
    platform: str
    kind: str  # 'handle' | 'phone'
    value: str


_RESERVED_PATHS = {
    "telegram": {"joinchat", "c", "s", "addstickers", "share", "iv", "proxy", "socks", "login"},
    "x": {"i", "intent", "search", "hashtag", "share", "home", "explore", "settings", "messages", "notifications"},
    "facebook": {"profile.php", "pages", "groups", "watch", "share", "sharer", "sharer.php", "l.php", "photo",
                 "photo.php", "permalink.php", "people", "public", "events", "marketplace", "help", "policies",
                 "login", "dialog", "plugins", "story.php"},
}
_PLATFORM_HOSTS = {
    "t.me": "telegram", "telegram.me": "telegram", "telegram.dog": "telegram",
    "x.com": "x", "twitter.com": "x", "www.twitter.com": "x", "mobile.twitter.com": "x",
    "facebook.com": "facebook", "www.facebook.com": "facebook", "m.facebook.com": "facebook", "fb.com": "facebook",
    "tiktok.com": "tiktok", "www.tiktok.com": "tiktok",
    "youtube.com": "youtube", "www.youtube.com": "youtube", "m.youtube.com": "youtube",
    "snapchat.com": "snapchat", "www.snapchat.com": "snapchat",
}
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")


def social_ref(info: UrlInfo) -> SocialRef | None:
    """Extract an account handle (or a phone number for WhatsApp links) from a social URL."""
    segs = [s for s in info.path.split("/") if s]
    if info.host == "wa.me" and segs and re.fullmatch(r"\+?\d{6,15}", segs[0]):
        return SocialRef("whatsapp", "phone", "+" + segs[0].lstrip("+"))
    if info.host in ("api.whatsapp.com", "web.whatsapp.com", "wa.me"):
        for key, value in parse_qsl(info.query):
            if key == "phone" and re.fullmatch(r"\+?\d{6,15}", value):
                return SocialRef("whatsapp", "phone", "+" + value.lstrip("+"))
        return None
    platform = _PLATFORM_HOSTS.get(info.host)
    if platform is None or not segs:
        return None
    first = segs[0]
    if platform in ("tiktok", "youtube"):
        if first.startswith("@") and _NAME_RE.match(first[1:]):
            return SocialRef(platform, "handle", first[1:].lower())
        return None
    if platform == "snapchat":
        if first == "add" and len(segs) >= 2 and _NAME_RE.match(segs[1]):
            return SocialRef(platform, "handle", segs[1].lower())
        return None
    if first.lower() in _RESERVED_PATHS.get(platform, set()):
        return None
    name = first.lstrip("@")
    if _NAME_RE.match(name):
        return SocialRef(platform, "handle", name.lower())
    return None
