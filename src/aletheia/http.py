"""A deliberately small, hardened HTTP(S) client built on the standard library.

Security properties (each is covered by tests):

* **SSRF protection with DNS pinning.** The host is resolved once, every address must be a *global*
  (public) address, and the TCP connection is made to that exact IP while TLS still verifies the
  original host name. A redirect to ``169.254.169.254`` or ``localhost`` is refused before any
  connection is attempted, and DNS rebinding cannot swap the address between check and use.
* **Bounded resources.** Connect/read timeouts, a total deadline (slow-loris), a response size cap,
  gzip decompression with a cap (decompression bombs) and a redirect limit.
* **Polite behaviour.** Honest default User-Agent, per-host rate limit, retry with jittered
  exponential back-off that honours ``Retry-After``, and robots.txt support (RFC 9309 semantics).
* **No credentials, no cookies, no proxies.** The client never sends authentication data.
  For anonymity, route the whole machine through a VPN/Tor rather than relying on this client.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import random
import socket
import ssl
import time
import urllib.robotparser
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit

from . import __version__
from .errors import (
    BlockedTargetError,
    NetworkError,
    ResponseTooLargeError,
    RobotsDisallowedError,
    TlsError,
    TooManyRedirectsError,
    TransportError,
    ValidationError,
)

DEFAULT_UA = f"Aletheia/{__version__} (evidence capture; passive)"
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
RETRY_STATUS = frozenset({429, 502, 503, 504})
_PORTS = {"http": 80, "https": 443}

Resolver = Callable[[str, int], list[str]]


@dataclass(frozen=True)
class HttpPolicy:
    timeout: float = 15.0
    total_timeout: float = 60.0
    max_bytes: int = 10 * 1024 * 1024
    max_redirects: int = 5
    max_attempts: int = 3
    backoff_base: float = 0.5
    backoff_cap: float = 8.0
    retry_after_cap: float = 30.0
    min_interval: float = 1.0
    allow_private: bool = False
    allow_ips: frozenset[str] = frozenset()
    verify_tls: bool = True
    user_agent: str = DEFAULT_UA
    respect_robots: bool = True


@dataclass
class Hop:
    url: str
    status: int
    location: str | None
    remote_ip: str | None
    elapsed_ms: int


@dataclass
class HttpResult:
    requested_url: str
    final_url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    chain: list[Hop] = field(default_factory=list)
    remote_ip: str | None = None
    tls: dict | None = None
    tls_verified: bool = True
    elapsed_ms: int = 0
    attempts: int = 1
    decoded_gzip: bool = False
    started_at: str = ""
    user_agent: str = DEFAULT_UA

    def header(self, name: str) -> str | None:
        lname = name.lower()
        return next((v for k, v in self.headers if k.lower() == lname), None)

    @property
    def content_type(self) -> str | None:
        raw = self.header("Content-Type")
        return raw.split(";", 1)[0].strip().lower() if raw else None

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


# --- helpers ---------------------------------------------------------------------------------


def default_resolver(host: str, port: int) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TransportError(host=host, detail=f"DNS: {exc.strerror or exc}") from exc
    seen: list[str] = []
    for info in infos:
        ip = str(info[4][0]).split("%", 1)[0]
        if ip not in seen:
            seen.append(ip)
    if not seen:
        raise TransportError(host=host, detail="DNS: no addresses")
    return seen


def is_public_ip(ip_str: str) -> bool:
    """True only for globally routable unicast addresses (defence in depth on top of ``is_global``)."""
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    special = ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_private
    return ip.is_global and not special


def _connect_pinned(ips: list[str], port: int, timeout: float) -> socket.socket:
    last: OSError | None = None
    for ip in ips:
        try:
            sock = socket.create_connection((ip, port), timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock
        except OSError as exc:
            last = exc
    raise last or OSError("no address to connect to")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ips: list[str], timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ips = ips

    def connect(self) -> None:
        self.sock = _connect_pinned(self._ips, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ips: list[str], timeout: float, ctx: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._ips = ips
        self._ctx = ctx

    def connect(self) -> None:
        raw = _connect_pinned(self._ips, self.port, self.timeout)
        self.sock = self._ctx.wrap_socket(raw, server_hostname=self.host)


def _name_tuple(rdn: tuple) -> dict[str, str]:
    return {k: v for part in rdn for k, v in part}


def tls_info(sock: socket.socket | None) -> dict | None:
    """JSON-friendly facts about the TLS session (certificate fingerprint always, details if verified)."""
    if not isinstance(sock, ssl.SSLSocket):
        return None
    info: dict = {"version": sock.version(), "cipher": (sock.cipher() or ("",))[0]}
    der = sock.getpeercert(binary_form=True)
    if der:
        info["cert_sha256"] = hashlib.sha256(der).hexdigest()
    cert = sock.getpeercert() or {}
    if cert:
        info["subject"] = _name_tuple(cert.get("subject", ()))
        info["issuer"] = _name_tuple(cert.get("issuer", ()))
        info["not_before"] = cert.get("notBefore")
        info["not_after"] = cert.get("notAfter")
        info["san"] = [v for _, v in cert.get("subjectAltName", ())]
    return info


def _gunzip_limited(data: bytes, limit: int, url: str) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out: list[bytes] = []
    total = 0
    try:
        buf = data
        while buf:
            chunk = d.decompress(buf, 65536)
            total += len(chunk)
            if total > limit:
                raise ResponseTooLargeError(limit=limit, url=url)
            out.append(chunk)
            buf = d.unconsumed_tail
        tail = d.flush()
        total += len(tail)
        if total > limit:
            raise ResponseTooLargeError(limit=limit, url=url)
        out.append(tail)
    except zlib.error as exc:
        raise TransportError(host=urlsplit(url).hostname or "", detail=f"invalid gzip body: {exc}") from exc
    return b"".join(out)


# --- client ----------------------------------------------------------------------------------


class HttpClient:
    def __init__(
        self,
        policy: HttpPolicy | None = None,
        *,
        resolver: Resolver = default_resolver,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        rng: Callable[[], float] = random.random,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.policy = policy or HttpPolicy()
        self._resolve = resolver
        self._sleep = sleep
        self._mono = monotonic
        self._rng = rng
        self._clock = clock
        self._last: dict[str, float] = {}
        self._robots: dict[str, urllib.robotparser.RobotFileParser | bool] = {}

    # -- guards -------------------------------------------------------------------------------

    def _check_url(self, url: str) -> tuple[str, str, int]:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise ValidationError(key="error.validation.url", url=url) from exc
        scheme = parts.scheme.lower()
        if scheme not in _PORTS:
            raise ValidationError(key="error.validation.scheme", url=url)
        if not parts.hostname:
            raise ValidationError(key="error.validation.url", url=url)
        if "@" in parts.netloc:
            raise ValidationError(key="error.validation.credentials")
        return scheme, parts.hostname, port or _PORTS[scheme]

    def _addresses(self, host: str, port: int) -> list[str]:
        ips = self._resolve(host, port)
        if not self.policy.allow_private:
            for ip in ips:
                if not is_public_ip(ip) and ip not in self.policy.allow_ips:
                    raise BlockedTargetError(host=host, ip=ip)
        return ips

    def _throttle(self, host: str) -> None:
        last = self._last.get(host)
        if last is not None:
            wait = self.policy.min_interval - (self._mono() - last)
            if wait > 0:
                self._sleep(wait)
        self._last[host] = self._mono()

    def _retry_delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                seconds = float(retry_after)
            except ValueError:
                try:
                    seconds = (parsedate_to_datetime(retry_after) - self._clock()).total_seconds()
                except (TypeError, ValueError):
                    seconds = 0.0
            return max(0.0, min(seconds, self.policy.retry_after_cap))
        ceiling = min(self.policy.backoff_cap, self.policy.backoff_base * 2 ** (attempt - 1))
        return self._rng() * ceiling

    # -- one request --------------------------------------------------------------------------

    def _fetch_once(self, url: str, *, verify_tls: bool, max_bytes: int, user_agent: str,
                    headers: dict[str, str] | None) -> HttpResult:
        scheme, host, port = self._check_url(url)
        self._throttle(host)
        ips = self._addresses(host, port)
        if scheme == "https":
            ctx = ssl.create_default_context()
            if not verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = _PinnedHTTPSConnection(host, port, ips, self.policy.timeout, ctx)
        else:
            conn = _PinnedHTTPConnection(host, port, ips, self.policy.timeout)
        parts = urlsplit(url)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        req_headers = {"User-Agent": user_agent, "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"}
        req_headers.update(headers or {})
        started = self._mono()
        try:
            conn.request("GET", path, headers=req_headers)
            sock = conn.sock
            tls = tls_info(sock) if scheme == "https" else None
            try:
                remote_ip = str(sock.getpeername()[0]) if sock else None
            except OSError:
                remote_ip = None
            resp = conn.getresponse()
            chunks: list[bytes] = []
            total = 0
            while True:
                if self._mono() - started > self.policy.total_timeout:
                    raise TransportError(host=host, detail="total time limit exceeded")
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ResponseTooLargeError(limit=max_bytes, url=url)
                chunks.append(chunk)
            body = b"".join(chunks)
            decoded = False
            if (resp.getheader("Content-Encoding") or "").lower().strip() in ("gzip", "x-gzip"):
                body, decoded = _gunzip_limited(body, max_bytes, url), True
            return HttpResult(
                requested_url=url, final_url=url, status=resp.status, reason=resp.reason or "",
                headers=[(k, v) for k, v in resp.getheaders()], body=body, remote_ip=remote_ip, tls=tls,
                tls_verified=verify_tls, elapsed_ms=int((self._mono() - started) * 1000), decoded_gzip=decoded,
                user_agent=user_agent,
            )
        except ssl.SSLCertVerificationError as exc:
            raise TlsError(host=host, detail=exc.verify_message or str(exc)) from exc
        except NetworkError:
            raise
        except ssl.SSLError as exc:
            raise TransportError(host=host, detail=f"TLS: {exc.reason or exc}") from exc
        except TimeoutError as exc:
            raise TransportError(host=host, detail="timeout") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(host=host, detail=str(exc) or exc.__class__.__name__) from exc
        finally:
            conn.close()

    def _fetch_with_retries(self, url: str, **kw) -> tuple[HttpResult, int]:
        attempts = max(1, self.policy.max_attempts)
        for attempt in range(1, attempts + 1):
            try:
                result = self._fetch_once(url, **kw)
            except TransportError:
                if attempt == attempts:
                    raise
                self._sleep(self._retry_delay(attempt, None))
                continue
            if result.status in RETRY_STATUS and attempt < attempts:
                self._sleep(self._retry_delay(attempt, result.header("Retry-After")))
                continue
            return result, attempt
        raise AssertionError("unreachable")  # pragma: no cover

    # -- robots.txt ---------------------------------------------------------------------------

    def robots_allows(self, url: str, user_agent: str) -> bool:
        scheme, host, port = self._check_url(url)
        origin = f"{scheme}://{urlsplit(url).netloc}"
        entry = self._robots.get(origin)
        if entry is None:
            try:
                res = self.get(f"{origin}/robots.txt", max_bytes=512 * 1024, check_robots=False)
                if res.status == 200:
                    parser = urllib.robotparser.RobotFileParser()
                    parser.parse(res.body.decode("utf-8", errors="replace").splitlines())
                    entry = parser
                elif res.status >= 500:
                    entry = False  # RFC 9309: server error -> assume complete disallow
                else:
                    entry = True  # 4xx: no robots file -> everything allowed
            except NetworkError:
                entry = False  # unreachable -> assume complete disallow
            self._robots[origin] = entry
        if entry is True:
            return True
        if entry is False:
            return False
        token = user_agent.split("/", 1)[0].strip() or "*"
        return entry.can_fetch(token, url)

    # -- public API ---------------------------------------------------------------------------

    def get(
        self,
        url: str,
        *,
        max_bytes: int | None = None,
        verify_tls: bool | None = None,
        user_agent: str | None = None,
        headers: dict[str, str] | None = None,
        check_robots: bool | None = None,
    ) -> HttpResult:
        """GET ``url`` following redirects safely. Every hop is re-validated against the SSRF rules."""
        ua = user_agent or self.policy.user_agent
        limit = max_bytes if max_bytes is not None else self.policy.max_bytes
        verify = self.policy.verify_tls if verify_tls is None else verify_tls
        robots = self.policy.respect_robots if check_robots is None else check_robots
        started_at = self._clock().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        t0 = self._mono()
        current, chain, attempts_total = url, [], 0
        for _ in range(self.policy.max_redirects + 1):
            if robots and not self.robots_allows(current, ua):
                raise RobotsDisallowedError(url=current)
            result, attempts = self._fetch_with_retries(current, verify_tls=verify, max_bytes=limit,
                                                        user_agent=ua, headers=headers)
            attempts_total += attempts
            location = result.header("Location") if result.status in REDIRECT_CODES else None
            chain.append(Hop(current, result.status, location, result.remote_ip, result.elapsed_ms))
            if not location:
                result.requested_url, result.final_url = url, current
                result.chain, result.attempts = chain, attempts_total
                result.started_at = started_at
                result.elapsed_ms = int((self._mono() - t0) * 1000)
                return result
            current = urljoin(current, location)
        raise TooManyRedirectsError(url=url, limit=self.policy.max_redirects)
