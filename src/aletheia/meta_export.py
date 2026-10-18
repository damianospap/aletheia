"""Reader for Meta's "Download your information" exports (Instagram / Facebook), JSON format.

Two real-world problems are solved here:

1. **Mojibake.** Meta's JSON export writes UTF-8 bytes as if they were Latin-1 code points, so
   Greek text arrives as ``Î\\x9aÎ±Î»Î·Î¼Î­ÏÎ±``. ``fix_mojibake`` reverses this losslessly and leaves
   already-correct strings untouched.
2. **Hostile archives.** Exports are big ZIPs from a user's device. We never extract: members are
   read in memory with size/ratio limits, and names with ``..``, absolute paths or drive letters
   are rejected (zip-slip). Directory sources never follow symlinks out of the root.

The export layout is not a public contract, so parsing is tolerant: unknown fields are ignored and
missing ones default to empty values.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ParseError, UnsafeArchiveError

MAX_JSON_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 500_000
MAX_TOTAL_READ = 2 * 1024**3
MAX_RATIO = 1000  # uncompressed / compressed

_THREAD_RE = re.compile(
    r"(?:^|/)messages/(inbox|filtered_threads|message_requests|archived_threads)/([^/]+)/message_(\d+)\.json$"
)


# --- mojibake --------------------------------------------------------------------------------


def fix_mojibake(s: str) -> str:
    """Repair UTF-8 text that was decoded as Latin-1; return ``s`` unchanged if it is not mojibake."""
    if s.isascii():
        return s
    try:
        return s.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def fix_tree(obj: Any) -> Any:
    """Apply ``fix_mojibake`` to every string (keys and values) in a decoded JSON tree."""
    if isinstance(obj, str):
        return fix_mojibake(obj)
    if isinstance(obj, list):
        return [fix_tree(v) for v in obj]
    if isinstance(obj, dict):
        return {fix_mojibake(k) if isinstance(k, str) else k: fix_tree(v) for k, v in obj.items()}
    return obj


# --- sources ---------------------------------------------------------------------------------


def _normalise(name: str) -> str:
    return name.replace("\\", "/")


def _unsafe(name: str) -> bool:
    n = _normalise(name)
    return n.startswith("/") or bool(re.match(r"^[A-Za-z]:", n)) or ".." in n.split("/") or "\x00" in n


class ExportSource:
    """A directory or ZIP file containing a Meta export. Use as a context manager."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._zip: zipfile.ZipFile | None = None
        self._read_total = 0
        if not self.path.exists():
            raise ParseError(detail=f"{self.path}: not found")

    def __enter__(self) -> "ExportSource":
        if self.path.is_file():
            try:
                self._zip = zipfile.ZipFile(self.path)
            except zipfile.BadZipFile as exc:
                raise ParseError(detail=f"{self.path.name}: not a valid ZIP file") from exc
            infos = self._zip.infolist()
            if len(infos) > MAX_MEMBERS:
                raise UnsafeArchiveError(name=f"{len(infos)} entries")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._zip:
            self._zip.close()

    def members(self) -> Iterator[str]:
        """Relative POSIX-style member names (unsafe ones raise ``UnsafeArchiveError``)."""
        if self._zip:
            for info in self._zip.infolist():
                if info.is_dir():
                    continue
                if _unsafe(info.filename):
                    raise UnsafeArchiveError(name=info.filename)
                yield _normalise(info.filename)
        else:
            root = self.path.resolve()
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
                for fname in filenames:
                    full = Path(dirpath, fname)
                    if full.is_symlink():
                        continue
                    yield full.relative_to(root).as_posix()

    def read(self, name: str, limit: int | None = None) -> bytes:
        limit = MAX_JSON_BYTES if limit is None else limit
        if self._zip:
            info = None
            for candidate in self._zip.infolist():
                if _normalise(candidate.filename) == name:
                    info = candidate
                    break
            if info is None:
                raise ParseError(detail=f"missing member: {name}")
            if info.file_size > limit:
                raise UnsafeArchiveError(name=f"{name} ({info.file_size} bytes)")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO and info.file_size > 10_000_000:
                raise UnsafeArchiveError(name=f"{name} (compression ratio)")
            self._read_total += info.file_size
            if self._read_total > MAX_TOTAL_READ:
                raise UnsafeArchiveError(name="total size")
            with self._zip.open(info) as fh:
                data = fh.read(limit + 1)
            if len(data) > limit:
                raise UnsafeArchiveError(name=name)
            return data
        full = (self.path / name).resolve()
        if self.path.resolve() not in full.parents:
            raise UnsafeArchiveError(name=name)
        if full.stat().st_size > limit:
            raise UnsafeArchiveError(name=f"{name} ({full.stat().st_size} bytes)")
        return full.read_bytes()

    def sha256_of_container(self) -> str | None:
        """SHA-256 of the ZIP file itself (``None`` for directory sources)."""
        if not self._zip:
            return None
        h = hashlib.sha256()
        with open(self.path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()


# --- threads ---------------------------------------------------------------------------------


@dataclass
class Message:
    ts_ms: int | None
    sender: str
    text: str
    links: list[str] = field(default_factory=list)
    media: list[str] = field(default_factory=list)

    @property
    def iso(self) -> str:
        if self.ts_ms is None:
            return "unknown"
        return datetime.fromtimestamp(self.ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Thread:
    folder: str  # e.g. "message_requests/someone_123"
    title: str
    participants: list[str]
    messages: list[Message]
    members: list[tuple[str, str]]  # (member name, sha256 of its bytes) - provenance
    raw_members: list[tuple[str, bytes]] = field(default_factory=list, repr=False)  # original bytes

    def transcript(self) -> str:
        """A plain-text, chronologically ordered rendering suitable for indicator extraction."""
        lines = []
        for m in self.messages:
            parts = [m.text] if m.text else []
            parts += [f"<link: {u}>" for u in m.links]
            parts += [f"<attachment: {u}>" for u in m.media]
            lines.append(f"[{m.iso}] {m.sender}: {' '.join(parts) if parts else '<no text>'}")
        return "\n".join(lines) + ("\n" if lines else "")


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def parse_thread_json(obj: Any, member: str) -> tuple[str, list[str], list[Message]]:
    if not isinstance(obj, dict) or not isinstance(obj.get("messages"), list):
        raise ParseError(detail=f"{member}: no 'messages' list")
    obj = fix_tree(obj)
    title = obj.get("title") if isinstance(obj.get("title"), str) else ""
    participants = [p["name"] for p in obj.get("participants", []) if isinstance(p, dict) and isinstance(p.get("name"), str)]
    messages: list[Message] = []
    for raw in obj["messages"]:
        if not isinstance(raw, dict):
            continue
        links: list[str] = []
        share = raw.get("share")
        if isinstance(share, dict):
            if isinstance(share.get("link"), str):
                links.append(share["link"])
            if isinstance(share.get("share_text"), str) and share["share_text"]:
                links.append(share["share_text"])
        media = [
            item["uri"]
            for key in ("photos", "videos", "audio_files", "files")
            for item in (raw.get(key) or [])
            if isinstance(item, dict) and isinstance(item.get("uri"), str)
        ]
        messages.append(
            Message(
                ts_ms=_as_int(raw.get("timestamp_ms")),
                sender=raw.get("sender_name") if isinstance(raw.get("sender_name"), str) else "?",
                text=raw.get("content") if isinstance(raw.get("content"), str) else "",
                links=links,
                media=media,
            )
        )
    return title, participants, messages


def iter_threads(source: ExportSource) -> Iterator[Thread]:
    """Yield merged threads (all ``message_N.json`` chunks of a folder, oldest message first)."""
    groups: dict[str, list[tuple[int, str]]] = {}
    for name in source.members():
        m = _THREAD_RE.search(name)
        if m:
            folder = f"{m.group(1)}/{m.group(2)}"
            groups.setdefault(folder, []).append((int(m.group(3)), name))
    if not groups:
        raise ParseError(detail="no message threads found (expected messages/inbox/<thread>/message_N.json)")
    for folder in sorted(groups):
        title, participants, messages = "", [], []
        members: list[tuple[str, str]] = []
        raw_members: list[tuple[str, bytes]] = []
        for _, name in sorted(groups[folder]):
            data = source.read(name)
            try:
                obj = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ParseError(detail=f"{name}: invalid JSON ({exc.__class__.__name__})") from exc
            t, p, msgs = parse_thread_json(obj, name)
            title = title or t
            for who in p:
                if who not in participants:
                    participants.append(who)
            messages.extend(msgs)
            members.append((name, hashlib.sha256(data).hexdigest()))
            raw_members.append((name, data))
        messages.sort(key=lambda m: (m.ts_ms is None, m.ts_ms or 0))
        yield Thread(folder, title, participants, messages, members, raw_members)
