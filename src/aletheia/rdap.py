"""Domain registration data via RDAP (RFC 7480-7484), the structured successor of WHOIS.

Exposure is *passive*: IANA and the registry's RDAP server learn which domain was queried; the
domain's own infrastructure is never contacted. Registrant details are normally redacted for
privacy (GDPR); this module reports that fact and never tries to un-redact anything.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import HttpStatusError, NetworkError, NoRdapServiceError, ValidationError
from .fsutil import atomic_write_bytes
from .http import HttpClient
from .indicators.urls import normalize_host, registrable_domain

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_RDAP_HEADERS = {"Accept": "application/rdap+json, application/json;q=0.9"}


@dataclass
class DomainRdap:
    domain: str
    found: bool = True
    handle: str | None = None
    status: list[str] = field(default_factory=list)
    registered: str | None = None
    last_changed: str | None = None
    expires: str | None = None
    registrar: str | None = None
    nameservers: list[str] = field(default_factory=list)
    registrant_redacted: bool = True
    source_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def parse_bootstrap(obj: Any) -> dict[str, str]:
    """TLD -> RDAP base URL (https preferred) from the IANA bootstrap document."""
    out: dict[str, str] = {}
    for service in (obj or {}).get("services", []):
        try:
            tlds, urls = service
        except (TypeError, ValueError):
            continue
        https = [u for u in urls if str(u).startswith("https://")]
        base = (https or list(urls) or [None])[0]
        if base:
            for tld in tlds:
                out[str(tld).lower()] = str(base)
    return out


def _vcard_fn(entity: dict[str, Any]) -> str | None:
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "fn":
                return str(item[3])
    except (KeyError, IndexError, TypeError):
        return None
    return None


def parse_domain(obj: dict[str, Any], domain: str, source_url: str = "") -> DomainRdap:
    events = {e.get("eventAction"): e.get("eventDate") for e in obj.get("events", []) if isinstance(e, dict)}
    registrar = None
    registrant_visible = False
    for ent in obj.get("entities", []):
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in ent.get("roles", [])]
        if "registrar" in roles and registrar is None:
            registrar = _vcard_fn(ent)
        if "registrant" in roles:
            fn = (_vcard_fn(ent) or "").lower()
            if fn and "redacted" not in fn and "privacy" not in fn:
                registrant_visible = True
    return DomainRdap(
        domain=domain, found=True, handle=obj.get("handle"),
        status=[str(s) for s in obj.get("status", [])],
        registered=events.get("registration"), last_changed=events.get("last changed"),
        expires=events.get("expiration"), registrar=registrar,
        nameservers=sorted(str(n["ldhName"]).lower() for n in obj.get("nameservers", []) if isinstance(n, dict) and n.get("ldhName")),
        registrant_redacted=not registrant_visible, source_url=source_url,
    )


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def domain_age_days(info: DomainRdap, now: datetime) -> int | None:
    registered = _parse_dt(info.registered)
    return max(0, (now - registered).days) if registered else None


class RdapClient:
    def __init__(self, http: HttpClient, cache_dir: Path | None = None, *, ttl: float = 86400.0,
                 clock=lambda: datetime.now(timezone.utc)) -> None:
        self._http = http
        self._cache = Path(cache_dir) / "rdap-bootstrap.json" if cache_dir else None
        self._ttl = ttl
        self._clock = clock
        self._tlds: dict[str, str] | None = None

    def _load_bootstrap(self) -> dict[str, str]:
        if self._tlds is not None:
            return self._tlds
        if self._cache and self._cache.is_file() and time.time() - self._cache.stat().st_mtime < self._ttl:
            try:
                self._tlds = parse_bootstrap(json.loads(self._cache.read_text(encoding="utf-8")))
                return self._tlds
            except (OSError, json.JSONDecodeError):
                pass
        res = self._http.get(BOOTSTRAP_URL, max_bytes=2 * 1024 * 1024, check_robots=False)
        if res.status != 200:
            raise HttpStatusError(status=res.status, url=BOOTSTRAP_URL)
        try:
            obj = json.loads(res.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NetworkError(detail="invalid RDAP bootstrap document", key="error.net.invalid_response") from exc
        self._tlds = parse_bootstrap(obj)
        if self._cache:
            try:
                self._cache.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_bytes(self._cache, res.body)
            except OSError:
                pass  # caching is an optimisation only
        return self._tlds

    def lookup(self, domain: str) -> tuple[DomainRdap, bytes]:
        """Return the parsed record and the raw JSON bytes (to be stored as evidence)."""
        host, _uni, kind = normalize_host(domain)
        if kind != "domain":
            raise ValidationError(key="error.validation.domain", value=domain)
        name = registrable_domain(host)
        tld = host.rsplit(".", 1)[-1]
        base = self._load_bootstrap().get(tld)
        if not base:
            raise NoRdapServiceError(tld=tld)
        url = f"{base.rstrip('/')}/domain/{name}"
        res = self._http.get(url, headers=_RDAP_HEADERS, max_bytes=2 * 1024 * 1024, check_robots=False)
        if res.status == 404:
            return DomainRdap(domain=name, found=False, source_url=url), res.body
        if res.status != 200:
            raise HttpStatusError(status=res.status, url=url)
        try:
            obj = json.loads(res.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NetworkError(detail="invalid RDAP response", key="error.net.invalid_response") from exc
        return parse_domain(obj, name, url), res.body
