"""Shared test infrastructure (standard library only)."""

from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from aletheia.http import HttpClient, HttpPolicy
from aletheia.models import Purpose
from aletheia.vault import Vault

START = datetime(2026, 10, 14, 9, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    """Deterministic, strictly increasing clock (one second per call)."""

    def __init__(self, start: datetime = START, step: float = 1.0) -> None:
        self.t = start
        self.step = timedelta(seconds=step)
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            self.t += self.step
            return self.t


class VaultTestCase(unittest.TestCase):
    """Provides ``self.home`` (temp dir), ``self.vault`` and a helper to make a case."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name) / "home"
        self.clock = FakeClock()
        self.vault = Vault(self.home, clock=self.clock)

    def new_case(self, title: str = "Test case", purpose: Purpose = Purpose.VICTIM_REPORT):
        case = self.vault.create_case(title, purpose, accept_aup=True)
        self.addCleanup(case.close)
        return case

    def tmp_path(self, name: str) -> Path:
        return Path(self._tmp.name) / name


# --- local web site for network tests ---------------------------------------------------------

_BOMB: list[bytes] = []


def gzip_bomb() -> bytes:
    """50 MiB of zeros, gzip-compressed (built once; about 50 KB)."""
    if not _BOMB:
        _BOMB.append(gzip.compress(b"\x00" * (50 * 1024 * 1024), 9))
    return _BOMB[0]


ROBOTS = "User-agent: *\nDisallow: /private\n"
HTML_PAGE = (
    "<html><body><p>Pay to IBAN GR16 0110 1250 0000 0001 2300 695 or call +30 694 123 4567.</p>"
    "<a href='https://evil.example.top/login'>login</a></body></html>"
)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # silence
        pass

    def _send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_GET(self) -> None:  # noqa: N802
        site: TestSite = self.server.site  # type: ignore[attr-defined]
        site.hits.append(self.path)
        path = self.path.split("?", 1)[0]
        n = site.counts[path] = site.counts.get(path, 0) + 1
        if path == "/ok":
            self._send(200, HTML_PAGE.encode(), {"Content-Type": "text/html; charset=utf-8"})
        elif path == "/text":
            self._send(200, b"hello", {"Content-Type": "text/plain"})
        elif path == "/png":
            self._send(200, b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, {"Content-Type": "image/png"})
        elif path == "/redir1":
            self._send(302, b"", {"Location": "/ok"})
        elif path == "/redir-meta":
            self._send(302, b"", {"Location": "http://169.254.169.254/latest/meta-data/"})
        elif path == "/loop":
            self._send(302, b"", {"Location": "/loop"})
        elif path == "/big":
            self._send(200, b"A" * (2 * 1024 * 1024), {"Content-Type": "application/octet-stream"})
        elif path == "/flaky":
            if n <= 2:
                self._send(503, b"busy", {"Retry-After": "1"})
            else:
                self._send(200, b"finally", {"Content-Type": "text/plain"})
        elif path == "/always503":
            self._send(503, b"down", {"Retry-After": "2"})
        elif path == "/gzip":
            self._send(200, gzip.compress(b"compressed hello"), {"Content-Encoding": "gzip", "Content-Type": "text/plain"})
        elif path == "/gzipbomb":
            self._send(200, gzip_bomb(), {"Content-Encoding": "gzip"})
        elif path == "/slow":
            time.sleep(1.5)
            self._send(200, b"late")
        elif path == "/headers":
            body = json.dumps({"ua": self.headers.get("User-Agent"), "host": self.headers.get("Host"),
                               "cookie": self.headers.get("Cookie"), "auth": self.headers.get("Authorization")})
            self._send(200, body.encode(), {"Content-Type": "application/json"})
        elif path == "/robots.txt":
            if site.robots_status == 200:
                self._send(200, site.robots.encode(), {"Content-Type": "text/plain"})
            else:
                self._send(site.robots_status, b"")
        elif path in ("/private", "/public"):
            self._send(200, b"page " + path.encode(), {"Content-Type": "text/plain"})
        else:
            self._send(404, b"nope", {"Content-Type": "text/plain"})


class TestSite:
    """A throw-away HTTP (or HTTPS) server on 127.0.0.1 with scripted routes."""

    def __init__(self, tls_cert: tuple[str, str] | None = None) -> None:
        self.hits: list[str] = []
        self.counts: dict[str, int] = {}
        self.robots = ROBOTS
        self.robots_status = 200
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.site = self  # type: ignore[attr-defined]
        self.tls = tls_cert is not None
        if tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls_cert)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"{'https' if self.tls else 'http'}://127.0.0.1:{self.port}"

    def __enter__(self) -> "TestSite":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def make_policy(**overrides) -> HttpPolicy:
    base = dict(allow_ips=frozenset({"127.0.0.1"}), min_interval=0.0, timeout=3.0, max_attempts=3)
    base.update(overrides)
    return HttpPolicy(**base)


def make_client(**overrides) -> HttpClient:
    """A client that may talk to 127.0.0.1, never really sleeps and records the delays."""
    sleeps: list[float] = []
    client = HttpClient(make_policy(**overrides), sleep=sleeps.append, rng=lambda: 0.5)
    client.sleeps = sleeps  # type: ignore[attr-defined]
    return client


def make_self_signed(dirpath: Path) -> tuple[str, str] | None:
    """Create a throw-away self-signed certificate with the openssl CLI (None if unavailable)."""
    if shutil.which("openssl") is None:
        return None
    cert, key = dirpath / "cert.pem", dirpath / "key.pem"
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-subj", "/CN=127.0.0.1", "-days", "1"],
        capture_output=True, timeout=60,
    )
    return (str(cert), str(key)) if proc.returncode == 0 and cert.exists() else None


# --- Instagram export fixtures ----------------------------------------------------------------


def to_mojibake(obj):
    """Encode like Meta's exporter: UTF-8 bytes written as Latin-1 code points."""
    if isinstance(obj, str):
        return obj.encode("utf-8").decode("latin-1")
    if isinstance(obj, list):
        return [to_mojibake(v) for v in obj]
    if isinstance(obj, dict):
        return {to_mojibake(k): to_mojibake(v) for k, v in obj.items()}
    return obj


def thread_json(messages, title="Scammer", participants=("Victim", "scam_acc")):
    return {"participants": [{"name": p} for p in participants], "messages": messages, "title": title,
            "is_still_participant": True, "thread_path": "inbox/x"}


def build_export_zip(path: Path, threads: dict[str, list[dict]], *, mojibake: bool = True) -> Path:
    """Write a Meta-style export ZIP. ``threads`` maps 'folder' -> list of message_N.json dicts."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for folder, chunks in threads.items():
            for i, obj in enumerate(chunks, 1):
                data = to_mojibake(obj) if mojibake else obj
                zf.writestr(f"your_instagram_activity/messages/{folder}/message_{i}.json",
                            json.dumps(data, ensure_ascii=True))
    return path


def silent_streams():
    return io.StringIO(), io.StringIO()


def env_for(home: Path, **extra: str) -> dict[str, str]:
    env = {"ALETHEIA_HOME": str(home), "PATH": os.environ.get("PATH", "")}
    env.update(extra)
    return env
