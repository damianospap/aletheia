"""Cross-evidence correlation (explainable, rule-based, no scoring black box).

Evidence items are linked when they share a *strong* indicator (IBAN, wallet, phone, email) or a
*medium* one (non-common domain, handle). Indicators that appear in unrelated cases all the time
(instagram.com, gmail.com, ...) are ignored via a stoplist. Indicators that sit close together in
the same evidence (e.g. a wallet right next to a phone number) are reported as co-occurring.
"""

from __future__ import annotations

import csv
import io
from collections import defaultdict
from itertools import combinations
from typing import Any

from .domains import load_brands
from .indicators.urls import registrable_domain
from .vault import Case

WEIGHTS = {"iban": 5, "wallet": 5, "phone": 4, "email": 4, "domain": 3, "handle": 3, "ip": 2, "url": 1}
CLUSTER_MIN_WEIGHT = 3
COOCCUR_TYPES = frozenset({"iban", "wallet", "phone", "email", "handle", "domain"})
COOCCUR_WINDOW = 300


def _stoplisted(itype: str, value: str, stop: frozenset[str]) -> bool:
    """Only domains are stoplisted; a mailbox address is always significant, even at gmail.com."""
    return itype == "domain" and registrable_domain(value) in stop


def correlate(case: Case) -> dict[str, Any]:
    _, stop = load_brands()
    obs = case.list_observations()
    ind_evidence: dict[tuple[str, str], set[str]] = defaultdict(set)
    for o in obs:
        if not _stoplisted(o.type, o.value, stop):
            ind_evidence[(o.type, o.value)].add(o.evidence_id)

    # union-find over evidence ids linked by shared indicators
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    linking: dict[tuple[str, str], set[str]] = {}
    for key, evs in ind_evidence.items():
        if WEIGHTS.get(key[0], 0) >= CLUSTER_MIN_WEIGHT and len(evs) >= 2:
            linking[key] = evs
            first, *rest = sorted(evs)
            for other in rest:
                parent[find(other)] = find(first)

    groups: dict[str, set[str]] = defaultdict(set)
    for evs in linking.values():
        for e in evs:
            groups[find(e)].add(e)
    clusters = []
    for n, (_, members) in enumerate(sorted(groups.items(), key=lambda kv: min(kv[1])), 1):
        shared = [{"type": t, "value": v, "evidence_count": len(evs)}
                  for (t, v), evs in sorted(linking.items()) if evs <= members]
        top = max(WEIGHTS[s["type"]] for s in shared)
        clusters.append({"id": n, "evidence_ids": sorted(members), "shared": shared,
                         "confidence": "high" if top >= 4 else "medium"})

    # co-occurrence within one evidence item
    by_ev: dict[str, list] = defaultdict(list)
    for o in obs:
        if o.type in COOCCUR_TYPES and not _stoplisted(o.type, o.value, stop):
            by_ev[o.evidence_id].append(o)
    pairs: dict[tuple[tuple[str, str], tuple[str, str]], set[str]] = defaultdict(set)
    for ev_id, items in by_ev.items():
        for a, b in combinations(items, 2):
            if (a.type, a.value) == (b.type, b.value) or (a.start, a.end) == (b.start, b.end):
                continue
            if abs(a.start - b.start) <= COOCCUR_WINDOW:
                key = tuple(sorted([(a.type, a.value), (b.type, b.value)]))
                pairs[key].add(ev_id)  # type: ignore[index]
    cooccurrence = [{"a": {"type": k[0][0], "value": k[0][1]}, "b": {"type": k[1][0], "value": k[1][1]},
                     "evidence_ids": sorted(v)} for k, v in sorted(pairs.items())]
    return {"clusters": clusters, "cooccurrence": cooccurrence}


def edges_csv(case: Case, result: dict[str, Any]) -> str:
    """Edge list (source,target,relation) importable into Maltego, Gephi or spreadsheets."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["source", "source_type", "target", "target_type", "relation"])
    seen = set()
    for o in case.list_observations():
        key = (o.type, o.value, o.evidence_id)
        if key not in seen:
            seen.add(key)
            w.writerow([o.value, o.type, o.evidence_id, "evidence", "observed_in"])
    for c in result["cooccurrence"]:
        w.writerow([c["a"]["value"], c["a"]["type"], c["b"]["value"], c["b"]["type"], "co_occurs"])
    return buf.getvalue()
