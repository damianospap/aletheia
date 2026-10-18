"""Offline domain-name analysis: internationalised names, mixed scripts and brand look-alikes."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

from .indicators.urls import host_mixed_script, normalize_host, registrable_domain
from .textnorm import confusable_skeleton


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]


@lru_cache(maxsize=1)
def load_brands() -> tuple[tuple[Brand, ...], frozenset[str]]:
    """Return ``(brands, stoplist_domains)`` from the bundled seed data."""
    text = resources.files("aletheia.packs").joinpath("brands.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)
    brands = tuple(Brand(b["name"], tuple(b["domains"])) for b in data.get("brand", []))
    return brands, frozenset(data.get("stoplist", {}).get("domains", []))


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@dataclass
class DomainSignals:
    domain: str  # ASCII / punycode
    unicode: str
    idn: bool
    mixed_script: bool  # any single label mixes scripts (e.g. Greek + Latin)
    skeleton: str
    lookalikes: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"domain": self.domain, "unicode": self.unicode, "idn": self.idn, "mixed_script": self.mixed_script,
                "skeleton": self.skeleton, "lookalikes": self.lookalikes}


def analyze_domain(domain: str) -> DomainSignals:
    host, host_uni, kind = normalize_host(domain)
    labels_uni = host_uni.split(".")
    reg_uni = registrable_domain(host_uni).split(".")
    sld = reg_uni[0]
    subs = labels_uni[: len(labels_uni) - len(reg_uni)]
    registrable = registrable_domain(host)
    signals = DomainSignals(
        domain=host,
        unicode=host_uni,
        idn=any(lbl.startswith("xn--") for lbl in host.split(".")),
        mixed_script=host_mixed_script(host_uni),
        skeleton=confusable_skeleton(sld),
    )
    if kind == "ip":
        return signals
    sld_tokens = [t for t in re.split(r"[-_0-9]+", sld) if t]
    sub_tokens = [t for s in subs for t in re.split(r"[-_0-9]+", s) if t]
    brands, _ = load_brands()
    for brand in brands:
        if registrable in brand.domains:
            continue
        for official in brand.domains:
            label = official.split(".")[0]
            skel = confusable_skeleton(label)
            kind_found = None
            if sld == label:
                kind_found = "same_name_other_tld"
            elif signals.skeleton == skel:
                kind_found = "homoglyph_or_typo"
            elif len(label) >= 6 and levenshtein(sld, label) == 1:
                kind_found = "near_typo"
            elif label in sld_tokens or (len(label) >= 5 and label in sld):
                kind_found = "brand_in_domain"
            elif label in sub_tokens or (len(label) >= 5 and any(label in s for s in subs)):
                kind_found = "brand_in_subdomain"
            if kind_found:
                signals.lookalikes.append({"brand": brand.name, "official": official, "kind": kind_found})
    return signals
