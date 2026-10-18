"""Run every extractor over a text and merge the results.

Conflicts (e.g. an IBAN's digits also looking like a phone number) are resolved by priority and
length. *Derived* indicators (the domain inside a URL, the handle inside an Instagram link, the
phone inside a wa.me link) share the span of their parent and never compete.
"""

from __future__ import annotations

import bisect
import ipaddress
import re

from ..errors import ValidationError
from ..models import Confidence, IndicatorType, Match
from . import accounts, crypto, iban as iban_mod, phones, urls

EXTRACTOR_VERSION = "1"

_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
# Candidate IPv6 text (full or ``::``-compressed); real validation is done by ``ipaddress``.
_IPV6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:]{3,39}(?![\w:])")

# Lower number wins when spans overlap.
_PRIORITY = {"url": 0, "email": 1, "iban": 2, "wallet": 3, "phone": 4, "ip": 5, "handle_kw": 6, "handle": 7, "domain": 8}


class _Spans:
    """Non-overlapping interval set with O(log n) overlap queries."""

    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []

    def overlaps(self, start: int, end: int) -> bool:
        i = bisect.bisect_left(self.starts, end)
        return i > 0 and self.ends[i - 1] > start

    def add(self, start: int, end: int) -> None:
        i = bisect.bisect_left(self.starts, start)
        self.starts.insert(i, start)
        self.ends.insert(i, end)


def _domain_attrs(info: urls.UrlInfo) -> dict:
    return {"registrable": info.registrable, "idn": info.is_idn, "mixed_script": info.mixed_script,
            "unicode": info.host_unicode}


def _url_matches(text: str) -> list[tuple[str, Match, list[Match]]]:
    out: list[tuple[str, Match, list[Match]]] = []
    for start, end, raw in urls.find_urls(text):
        try:
            info = urls.parse_url(raw)
        except ValidationError:
            continue
        attrs: dict = {"host": info.host, "registrable": info.registrable, "idn": info.is_idn,
                       "mixed_script": info.mixed_script, "userinfo": info.has_userinfo}
        derived: list[Match] = []

        def add_derived(kind: IndicatorType, value: str, conf: Confidence, a: dict, _s=start, _e=end, _r=raw) -> None:
            derived.append(Match(kind, value, _r, _s, _e, conf, f"{kind.value}@{EXTRACTOR_VERSION}", a, True))

        def add_url_parts(i: urls.UrlInfo) -> None:
            if i.host_kind == "domain":
                add_derived(IndicatorType.DOMAIN, i.host, Confidence.HIGH, _domain_attrs(i))
            else:
                add_derived(IndicatorType.IP, i.host, Confidence.HIGH, {"global": _is_global(i.host)})
            ig = urls.classify_instagram(i)
            if ig:
                attrs.setdefault("ig_kind", ig.kind)
                if ig.shortcode:
                    attrs.setdefault("ig_shortcode", ig.shortcode)
                if ig.handle:
                    attrs.setdefault("ig_handle", ig.handle)
                    add_derived(IndicatorType.HANDLE, f"instagram:{ig.handle}", Confidence.HIGH,
                                {"platform": "instagram", "handle": ig.handle, "via": ig.kind})
            soc = urls.social_ref(i)
            if soc and soc.kind == "handle":
                add_derived(IndicatorType.HANDLE, f"{soc.platform}:{soc.value}", Confidence.HIGH,
                            {"platform": soc.platform, "handle": soc.value, "via": "url"})
            elif soc and soc.kind == "phone":
                ph = phones.normalize_phone(soc.value, default_region=None)
                if ph:
                    add_derived(IndicatorType.PHONE, ph.e164, ph.confidence,
                                {"region": ph.region, "line_type": ph.line_type, "via": soc.platform})

        add_url_parts(info)
        if info.unwrapped:
            attrs["unwrapped"] = info.unwrapped.canonical
            add_derived(IndicatorType.URL, info.unwrapped.canonical, Confidence.HIGH, {"via": "redirect_shim"})
            add_url_parts(info.unwrapped)
        out.append(("url", Match(IndicatorType.URL, info.canonical, raw, start, end, Confidence.HIGH,
                                 f"url@{EXTRACTOR_VERSION}", attrs), derived))
    return out


def _is_global(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def extract_indicators(text: str, *, default_region: str | None = "GR") -> list[Match]:
    """Extract all indicators from ``text`` (offsets refer to ``text``)."""
    v = EXTRACTOR_VERSION
    candidates: list[tuple[int, int, str, Match, list[Match]]] = []

    def push(kind: str, match: Match, derived: list[Match] | None = None) -> None:
        candidates.append((_PRIORITY[kind], -(match.end - match.start), kind, match, derived or []))

    for kind, match, derived in _url_matches(text):
        push(kind, match, derived)

    for s, e, raw in accounts.find_emails(text):
        try:
            em = accounts.parse_email(raw)
        except ValidationError:
            continue
        attrs = {"domain": em.domain}
        if em.alias_key:
            attrs["alias_key"] = em.alias_key
        derived = [Match(IndicatorType.DOMAIN, em.domain, raw, s, e, Confidence.MEDIUM, f"domain@{v}",
                         {"via": "email"}, True)]
        push("email", Match(IndicatorType.EMAIL, em.address, raw, s, e, Confidence.HIGH, f"email@{v}", attrs), derived)

    for s, e, info in iban_mod.find_ibans(text):
        push("iban", Match(IndicatorType.IBAN, info.iban, text[s:e], s, e, info.confidence, f"iban@{v}",
                           {"country": info.country, **({"bank_code": info.bank_code} if info.bank_code else {})}))

    for s, e, w in crypto.find_wallets(text):
        push("wallet", Match(IndicatorType.WALLET, f"{w.chain}:{w.address}", text[s:e], s, e, w.confidence,
                             f"wallet@{v}", {"chain": w.chain, "kind": w.kind, **({"note": w.note} if w.note else {})}))

    for s, e, raw in phones.find_phones(text):
        ph = phones.normalize_phone(raw, default_region=default_region)
        if ph:
            push("phone", Match(IndicatorType.PHONE, ph.e164, raw, s, e, ph.confidence, f"phone@{v}",
                                {k: val for k, val in (("region", ph.region), ("line_type", ph.line_type)) if val}))

    for rx in (_IPV4_RE, _IPV6_RE):
        for m in rx.finditer(text):
            raw = m.group(0)
            if rx is _IPV6_RE:
                if raw.count(":") < 2 or sum(c != ":" for c in raw) < 3:
                    continue  # times (12:34), MAC fragments, "a::b" and similar are not addresses
                raw = raw.rstrip(":") if not raw.endswith("::") else raw
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if ip.is_unspecified:
                continue
            push("ip", Match(IndicatorType.IP, str(ip), raw, m.start(), m.start() + len(raw),
                             Confidence.MEDIUM if ip.is_global else Confidence.LOW, f"ip@{v}", {"global": ip.is_global}))

    for s, e, raw, platform in accounts.find_handles(text):
        handle = raw.lstrip("@").lower()
        conf = Confidence.MEDIUM if platform == "instagram" else Confidence.LOW
        push("handle_kw" if platform == "instagram" else "handle",
             Match(IndicatorType.HANDLE, f"{platform}:{handle}", raw, s, e, conf, f"handle@{v}",
                   {"platform": platform, "handle": handle}))

    for s, e, raw, defanged in urls.find_bare_domains(text):
        try:
            host, host_uni, kind = urls.normalize_host(urls.refang(raw))
        except ValidationError:
            continue
        if kind != "domain":
            continue
        push("domain", Match(IndicatorType.DOMAIN, host, raw, s, e, Confidence.MEDIUM if defanged else Confidence.LOW,
                             f"domain@{v}", {"registrable": urls.registrable_domain(host), "unicode": host_uni,
                                             "idn": host != host_uni, "defanged": defanged,
                                             "mixed_script": urls.host_mixed_script(host_uni)}))

    candidates.sort(key=lambda c: (c[0], c[1], c[3].start))
    spans = _Spans()
    result: list[Match] = []
    for _prio, _neg_len, _kind, match, derived in candidates:
        if spans.overlaps(match.start, match.end):
            continue
        spans.add(match.start, match.end)
        result.append(match)
        result.extend(derived)
    result.sort(key=lambda m: (m.start, m.derived, m.type.value, m.value))
    return result


def context_for(text: str, match: Match, width: int = 60) -> str:
    """A short single-line snippet of ``text`` around ``match`` for evidence tables."""
    lo, hi = max(0, match.start - width), min(len(text), match.end + width)
    return re.sub(r"\s+", " ", text[lo:hi]).strip()
