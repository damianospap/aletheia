"""Filesystem helpers that behave the same on Windows, macOS, Linux and Termux/Android.

Everything here is about the places where those platforms differ: atomic replacement and
fsync, advisory locking, reserved/illegal file names, MAX_PATH, read-only attributes.
"""

from __future__ import annotations

import contextlib
import hashlib
import ntpath
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import unicodedata
from collections.abc import Iterable
from pathlib import Path
from types import TracebackType

from .errors import VaultLockedError

try:  # POSIX
    import fcntl  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - platform specific
    fcntl = None  # type: ignore[assignment]
try:  # Windows
    import msvcrt  # type: ignore[import-not-found]
except ImportError:
    msvcrt = None  # type: ignore[assignment]

CHUNK = 1024 * 1024
IS_WINDOWS = sys.platform == "win32"


# --- hashing ---------------------------------------------------------------------------------


def sha256_chunks(chunks: Iterable[bytes]) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    for chunk in chunks:
        h.update(chunk)
        size += len(chunk)
    return h.hexdigest(), size


def sha256_file(path: Path) -> tuple[str, int]:
    with open(path, "rb") as fh:
        return sha256_chunks(iter(lambda: fh.read(CHUNK), b""))


# --- atomic write ----------------------------------------------------------------------------


def _chmod_quiet(path: str | Path, mode: int) -> None:
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, mode)


def fsync_dir(path: Path) -> None:
    """Flush directory metadata (rename durability). No-op on Windows."""
    if IS_WINDOWS:
        return
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def replace_with_retry(src: str | Path, dst: str | Path, attempts: int = 6) -> None:
    """``os.replace`` with back-off: on Windows, AV scanners/indexers briefly lock new files."""
    delay = 0.02
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay *= 2


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` so that readers see either the old or the new content."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".part", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _chmod_quiet(tmp, mode)
        replace_with_retry(tmp, path)
        fsync_dir(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` (and parents) readable only by the current user where the OS supports it."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _chmod_quiet(path, 0o700)
    return path


# --- advisory lock ---------------------------------------------------------------------------


class FileLock:
    """Cross-process exclusive lock (``flock`` on POSIX, ``msvcrt.locking`` on Windows)."""

    def __init__(self, path: Path, timeout: float = 10.0, poll: float = 0.05) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self.poll = poll
        self._fd: int | None = None

    def acquire(self) -> None:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._try_lock(fd)
                self._fd = fd
                return
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise VaultLockedError(seconds=self.timeout) from None
                time.sleep(self.poll)

    @staticmethod
    def _try_lock(fd: int) -> None:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt is not None:  # pragma: no cover - Windows only
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        # else: no locking primitive available; fall through (single-process use)

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            elif msvcrt is not None:  # pragma: no cover - Windows only
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.release()


# --- names and paths -------------------------------------------------------------------------

_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
_ILLEGAL = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')


def safe_filename(name: str, max_len: int = 120) -> str:
    """Turn arbitrary text into a file name that is valid on every supported OS."""
    s = unicodedata.normalize("NFC", name)
    s = _ILLEGAL.sub("_", s).strip(" .")
    if not s:
        s = "file"
    stem = s.split(".", 1)[0]
    if stem.upper() in _WIN_RESERVED:
        s = "_" + s
    if len(s.encode("utf-8")) > max_len:
        digest = hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]
        keep = s.encode("utf-8")[: max_len - 9].decode("utf-8", errors="ignore")
        s = f"{keep}~{digest}"
    return s


def win_long_path(path: str, *, force: bool = False) -> str:
    """Return a ``\\\\?\\`` extended-length path for Windows when the path is long.

    ``force`` allows exercising the string logic on non-Windows hosts (used by tests).
    """
    if not (IS_WINDOWS or force):
        return path
    absolute = ntpath.abspath(path)
    if absolute.startswith("\\\\?\\"):
        return absolute
    if len(absolute) < 240:
        return path
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


# --- deletion --------------------------------------------------------------------------------


def _force_writable(func, path, _exc) -> None:  # type: ignore[no-untyped-def]
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    func(path)


def rmtree_force(path: Path) -> None:
    """``shutil.rmtree`` that also removes read-only files (Windows refuses otherwise)."""
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_force_writable)
    else:  # pragma: no cover
        shutil.rmtree(path, onerror=_force_writable)
