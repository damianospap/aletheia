"""Where are we running, where may we store data, and what does the filesystem support?

Covers Windows, macOS, Linux and Termux/Android. The Termux rules come from how Android
works: the app's private storage (``$HOME``) is a normal ext4/f2fs filesystem, whereas shared
storage (``/sdcard``, ``/storage/emulated``) is FUSE/FAT-like: no symlinks, no exec bit, no
real permissions and case-insensitive. Cases must never live there.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import tempfile
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .errors import UnsafeStorageError
from .fsutil import FileLock, atomic_write_bytes, ensure_private_dir

APP_DIR = "Aletheia"
_ANDROID_SHARED = ("/sdcard", "/storage/", "/mnt/sdcard", "/mnt/media_rw", "/mnt/runtime")


@dataclass(frozen=True)
class PlatformInfo:
    system: str  # windows | macos | linux | termux | android | other
    release: str
    machine: str
    python: str
    is_termux: bool
    stdout_encoding: str


def detect_system(
    env: Mapping[str, str] | None = None,
    sys_platform: str | None = None,
    exists: Callable[[str], bool] = os.path.exists,
) -> str:
    env = os.environ if env is None else env
    sp = sys.platform if sys_platform is None else sys_platform
    if sp == "win32":
        return "windows"
    if sp == "darwin":
        return "macos"
    termux = bool(env.get("TERMUX_VERSION")) or "com.termux" in env.get("PREFIX", "") or exists(
        "/data/data/com.termux/files/usr"
    )
    if termux:
        return "termux"
    if sp == "android":  # CPython 3.13+ official Android builds
        return "android"
    return "linux" if sp.startswith("linux") else "other"


def get_platform_info() -> PlatformInfo:
    system = detect_system()
    return PlatformInfo(
        system=system,
        release=platform.release(),
        machine=platform.machine(),
        python=platform.python_version(),
        is_termux=system == "termux",
        stdout_encoding=getattr(sys.stdout, "encoding", None) or "unknown",
    )


def default_home(env: Mapping[str, str], system: str, user_home: Path) -> Path:
    """Default data directory for ``system`` (pure function; easy to test)."""
    if system == "windows":
        base = env.get("LOCALAPPDATA")
        return Path(base) / APP_DIR if base else user_home / "AppData" / "Local" / APP_DIR
    if system == "macos":
        return user_home / "Library" / "Application Support" / APP_DIR
    xdg = env.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else user_home / ".local" / "share") / APP_DIR.lower()


def resolve_home(override: str | os.PathLike[str] | None = None, env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    chosen = override or env.get("ALETHEIA_HOME")
    if chosen:
        return Path(chosen).expanduser()
    return default_home(env, detect_system(env), Path.home())


def is_shared_storage(path: Path, system: str) -> bool:
    """True if ``path`` is on Android shared storage (after resolving symlinks)."""
    if system not in ("termux", "android"):
        return False
    real = os.path.realpath(path)
    return any(real == p.rstrip("/") or real.startswith(p if p.endswith("/") else p + "/") for p in _ANDROID_SHARED)


def ensure_home(home: Path, system: str | None = None) -> Path:
    """Create the data directory, refusing locations that cannot hold evidence safely."""
    system = system or detect_system()
    if is_shared_storage(home, system):
        raise UnsafeStorageError(path=str(home))
    return ensure_private_dir(home)


# --- filesystem capability probe -------------------------------------------------------------


@dataclass
class FsCapabilities:
    path: str
    atomic_replace: bool = False
    fsync: bool = False
    symlinks: bool = False
    exec_bit: bool = False
    private_mode: bool = False
    case_sensitive: bool = False
    unicode_names: bool = False
    long_paths: bool = False
    locking: bool = False
    shared_storage: bool = False
    free_bytes: int | None = None
    problems: list[str] = field(default_factory=list)  # catalog keys of failed *required* features

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _try(fn: Callable[[], bool]) -> bool:
    try:
        return bool(fn())
    except (OSError, NotImplementedError, ValueError):
        return False


def probe_filesystem(directory: Path, system: str | None = None) -> FsCapabilities:
    """Empirically test what the filesystem under ``directory`` supports."""
    system = system or detect_system()
    directory = Path(directory)
    caps = FsCapabilities(path=str(directory), shared_storage=is_shared_storage(directory, system))
    probe = Path(tempfile.mkdtemp(prefix=".aletheia-probe-", dir=directory))
    try:

        def atomic() -> bool:
            target = probe / "a.bin"
            atomic_write_bytes(target, b"one")
            atomic_write_bytes(target, b"two")
            return target.read_bytes() == b"two"

        def fsync() -> bool:
            with open(probe / "f.bin", "wb") as fh:
                fh.write(b"x")
                fh.flush()
                os.fsync(fh.fileno())
            return True

        def symlinks() -> bool:
            (probe / "t.txt").write_text("t")
            os.symlink("t.txt", probe / "link")
            return (probe / "link").read_text() == "t"

        def exec_bit() -> bool:
            p = probe / "x.sh"
            p.write_text("#!/bin/sh\n")
            os.chmod(p, 0o755)
            return os.access(p, os.X_OK) and system != "windows"

        def private_mode() -> bool:
            p = probe / "m.bin"
            p.write_bytes(b"m")
            os.chmod(p, 0o600)
            return (p.stat().st_mode & 0o077) == 0 and system != "windows"

        def case_sensitive() -> bool:
            (probe / "Aa").write_text("1")
            return not (probe / "aa").exists()

        def unicode_names() -> bool:
            nfd = unicodedata.normalize("NFD", "άλφα-ï")
            (probe / nfd).write_text("u")
            names = os.listdir(probe)
            return nfd in names or unicodedata.normalize("NFC", nfd) in names

        def long_paths() -> bool:
            deep = probe
            for _ in range(6):
                deep = deep / ("d" * 50)
            deep.mkdir(parents=True)
            (deep / "f.txt").write_text("deep")
            return (deep / "f.txt").read_text() == "deep"

        def locking() -> bool:
            lock = FileLock(probe / "l.lock", timeout=0.2)
            lock.acquire()
            lock.release()
            return True

        caps.atomic_replace = _try(atomic)
        caps.fsync = _try(fsync)
        caps.symlinks = _try(symlinks)
        caps.exec_bit = _try(exec_bit)
        caps.private_mode = _try(private_mode)
        caps.case_sensitive = _try(case_sensitive)
        caps.unicode_names = _try(unicode_names)
        caps.long_paths = _try(long_paths)
        caps.locking = _try(locking)
    finally:
        shutil.rmtree(probe, ignore_errors=True)
    try:
        caps.free_bytes = shutil.disk_usage(directory).free
    except OSError:
        caps.free_bytes = None
    # Only features Aletheia truly depends on are "problems"; the rest are informational.
    if not caps.atomic_replace:
        caps.problems.append("doctor.problem.atomic")
    if not caps.locking:
        caps.problems.append("doctor.problem.locking")
    if caps.shared_storage:
        caps.problems.append("doctor.problem.shared_storage")
    if not caps.private_mode and system != "windows":
        caps.problems.append("doctor.problem.private_mode")
    return caps
