"""Explainable scam-signal triage driven by TOML rule packs.

The output is a list of *signals* with human-readable explanations (in English and Greek), a score
and a coarse level. It is not a verdict about any person and has no learned component: every
signal can be traced to a rule and to the text that triggered it.

Greek packs (``lang = "el"``) are matched against *folded* text (no tonos, final sigma as sigma)
using a length-preserving fold, so reported offsets are valid for the original text.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from .errors import PackError
from .textnorm import fold_keep_length

MAX_TRIAGE_CHARS = 8_000_000
MAX_HITS_PER_RULE = 5
_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")


def lint_pattern(pattern: str) -> str | None:
    """Return a reason string if ``pattern`` is risky (catastrophic backtracking), else ``None``."""
    if len(pattern) > 2000:
        return "pattern too long"
    if _NESTED_QUANT.search(pattern):
        return "nested quantifier"
    return None


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: int
    pattern: re.Pattern[str]
    folded: bool
    explain: dict[str, str]


@dataclass(frozen=True)
class Pack:
    id: str
    lang: str
    version: int
    rules: tuple[Rule, ...]


def parse_pack(text: str, origin: str = "<memory>") -> Pack:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PackError(path=origin, detail=str(exc)) from exc
    meta = data.get("pack")
    if not isinstance(meta, dict) or not isinstance(meta.get("id"), str) or not isinstance(meta.get("lang"), str):
        raise PackError(path=origin, detail="[pack] needs string 'id' and 'lang'")
    rules: list[Rule] = []
    seen: set[str] = set()
    for i, raw in enumerate(data.get("rule", [])):
        where = f"rule #{i + 1}"
        if not isinstance(raw, dict):
            raise PackError(path=origin, detail=f"{where}: not a table")
        rid, cat, weight, pattern = raw.get("id"), raw.get("category"), raw.get("weight"), raw.get("pattern")
        if not (isinstance(rid, str) and isinstance(cat, str) and isinstance(pattern, str)):
            raise PackError(path=origin, detail=f"{where}: 'id', 'category', 'pattern' must be strings")
        if not isinstance(weight, int) or isinstance(weight, bool) or not 1 <= weight <= 5:
            raise PackError(path=origin, detail=f"{rid}: 'weight' must be an integer 1-5")
        if rid in seen:
            raise PackError(path=origin, detail=f"duplicate rule id: {rid}")
        seen.add(rid)
        risk = lint_pattern(pattern)
        if risk:
            raise PackError(path=origin, detail=f"{rid}: {risk}")
        try:
            compiled = re.compile(pattern, re.I | re.U)
        except re.error as exc:
            raise PackError(path=origin, detail=f"{rid}: invalid pattern ({exc})") from exc
        explain = {k[8:]: v for k, v in raw.items() if k.startswith("explain_") and isinstance(v, str)}
        rules.append(Rule(rid, cat, weight, compiled, meta["lang"] == "el", explain))
    version = meta.get("version", 1)
    return Pack(meta["id"], meta["lang"], version if isinstance(version, int) else 1, tuple(rules))


def load_pack_file(path: Path) -> Pack:
    try:
        return parse_pack(Path(path).read_text(encoding="utf-8"), str(path))
    except OSError as exc:
        raise PackError(path=str(path), detail=exc.strerror or str(exc)) from exc


def load_default_packs() -> list[Pack]:
    out = []
    for name in ("en-core.toml", "el-core.toml"):
        text = resources.files("aletheia.packs").joinpath(name).read_text(encoding="utf-8")
        out.append(parse_pack(text, name))
    return out


@dataclass(frozen=True)
class Hit:
    rule_id: str
    category: str
    weight: int
    start: int
    end: int
    snippet: str
    explain: dict[str, str]


@dataclass
class TriageResult:
    level: str  # none | low | medium | high
    score: int
    hits: list[Hit] = field(default_factory=list)
    categories: dict[str, int] = field(default_factory=dict)
    packs: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level, "score": self.score, "categories": self.categories, "packs": self.packs,
            "truncated": self.truncated,
            "hits": [{"rule": h.rule_id, "category": h.category, "weight": h.weight, "start": h.start,
                      "end": h.end, "snippet": h.snippet, "explain": h.explain} for h in self.hits],
        }


def _level(score: int) -> str:
    return "high" if score >= 8 else "medium" if score >= 4 else "low" if score >= 1 else "none"


def triage(text: str, packs: list[Pack] | None = None) -> TriageResult:
    packs = load_default_packs() if packs is None else packs
    truncated = len(text) > MAX_TRIAGE_CHARS
    text = text[:MAX_TRIAGE_CHARS]
    folded = fold_keep_length(text)
    hits: list[Hit] = []
    for pack in packs:
        for rule in pack.rules:
            haystack = folded if rule.folded else text
            for n, m in enumerate(rule.pattern.finditer(haystack)):
                if n >= MAX_HITS_PER_RULE:
                    break
                snippet = re.sub(r"\s+", " ", text[m.start() : m.end()]).strip()[:120]
                hits.append(Hit(rule.id, rule.category, rule.weight, m.start(), m.end(), snippet, rule.explain))
    per_rule: dict[str, int] = {}
    cat_of: dict[str, str] = {}
    for h in hits:
        per_rule[h.rule_id] = h.weight
        cat_of[h.rule_id] = h.category
    categories: dict[str, int] = {}
    for rid, weight in per_rule.items():
        categories[cat_of[rid]] = categories.get(cat_of[rid], 0) + weight
    categories = {c: min(5, s) for c, s in sorted(categories.items())}
    score = sum(categories.values())
    hits.sort(key=lambda h: (h.start, h.rule_id))
    return TriageResult(_level(score), score, hits, categories, [p.id for p in packs], truncated)
