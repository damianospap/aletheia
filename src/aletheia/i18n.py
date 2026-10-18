"""Tiny, dependency-free internationalisation layer (en-US and Greek).

Design notes:

* Catalogs are TOML files shipped as package data (``aletheia/locales``) and are read through
  ``importlib.resources`` so they also work inside a zipapp.
* Keys are flat dotted strings (``error.vault.locked``). Plural variants use the suffixes
  ``.one`` / ``.other`` (CLDR categories; both supported languages only need those two).
* A missing key falls back to English, then to the key itself. Formatting never raises:
  a missing placeholder is left visible as ``{name}``.
* Audit logs and machine output never use translated text; only presentation does.
"""

from __future__ import annotations

import os
import sys
import tomllib
from functools import lru_cache
from importlib import resources
from string import Formatter
from typing import Any, Mapping

SUPPORTED = ("en-US", "el")
DEFAULT_LANG = "en-US"
_FILES = {"en-US": "en_US.toml", "el": "el.toml"}


def normalize_lang(value: str | None) -> str | None:
    """Map assorted locale spellings to a supported tag, or ``None`` if unsupported."""
    if not value:
        return None
    v = value.strip().replace("_", "-").split(".", 1)[0].split("@", 1)[0].lower()
    if v in ("c", "posix", ""):
        return None
    if v == "el" or v.startswith("el-") or v.startswith("greek"):
        return "el"
    if v == "en" or v.startswith("en-") or v.startswith("english"):
        return "en-US"
    return None


def _windows_ui_locale() -> str | None:
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        buf = ctypes.create_unicode_buffer(85)
        if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, len(buf)):  # type: ignore[attr-defined]
            return buf.value
    except Exception:  # pragma: no cover - platform specific, best effort
        return None
    return None


def detect_lang(explicit: str | None = None, env: Mapping[str, str] | None = None) -> str:
    """Pick the UI language: explicit flag > ALETHEIA_LANG > POSIX env > OS locale > en-US."""
    env = os.environ if env is None else env
    if explicit:
        lang = normalize_lang(explicit)
        if lang:
            return lang
    for name in ("ALETHEIA_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        raw = env.get(name)
        if raw:
            # LANGUAGE may be a colon separated priority list.
            lang = normalize_lang(raw.split(":", 1)[0])
            if lang:
                return lang
    lang = normalize_lang(_windows_ui_locale())
    return lang or DEFAULT_LANG


def plural_category(lang: str, n: int) -> str:
    """CLDR plural category for integer ``n``. English and Greek: 'one' for 1, else 'other'."""
    return "one" if abs(n) == 1 else "other"


def _flatten(data: Mapping[str, Any], prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in data.items():
        full = f"{prefix}{key}"
        if isinstance(value, Mapping):
            out.update(_flatten(value, f"{full}."))
        else:
            out[full] = str(value)
    return out


@lru_cache(maxsize=None)
def load_catalog(lang: str) -> dict[str, str]:
    if lang not in _FILES:
        raise ValueError(f"unsupported language: {lang}")
    text = resources.files("aletheia.locales").joinpath(_FILES[lang]).read_text(encoding="utf-8")
    return _flatten(tomllib.loads(text))


def placeholders(template: str) -> set[str]:
    """Names of ``{placeholders}`` used in a template (used by catalog consistency tests)."""
    return {name for _, name, _, _ in Formatter().parse(template) if name}


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


class Translator:
    def __init__(self, lang: str | None = None) -> None:
        self.lang = normalize_lang(lang) or DEFAULT_LANG
        self._cat = load_catalog(self.lang)
        self._fallback = load_catalog(DEFAULT_LANG)

    def has(self, key: str) -> bool:
        return key in self._cat or key in self._fallback

    def __call__(self, key: str, **params: Any) -> str:
        template = self._cat.get(key) or self._fallback.get(key) or key
        try:
            return template.format_map(_SafeDict(params))
        except (ValueError, IndexError):  # malformed template: never crash the UI over a string
            return template

    def plural(self, key: str, n: int, **params: Any) -> str:
        """Translate ``key.one`` / ``key.other`` according to ``n`` (``{n}`` is always available)."""
        category = plural_category(self.lang, n)
        for suffix in (category, "other"):
            full = f"{key}.{suffix}"
            if self.has(full):
                return self(full, n=n, **params)
        return self(key, n=n, **params)
