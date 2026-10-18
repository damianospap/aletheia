"""Evidence reports in English and Greek (Markdown and self-contained HTML).

Two profiles:

* ``handover``: complete, for law enforcement, lawyers and editors.
* ``publication``: personal data (emails, phones, IBANs, handles) masked; no message text.
  Individual types can be revealed explicitly with ``reveal`` (the CLI audits every override).

All text goes through the translator; all dynamic values are escaped for the output format, so
hostile evidence (``<script>`` in a captured page) cannot inject markup into the HTML report.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any

from . import AUP_VERSION, __version__
from .correlate import correlate
from .i18n import Translator
from .ig_ids import decode as decode_ig
from .models import PERSONAL_TYPES, IndicatorType
from .policy import ReportProfile, mask_value
from .vault import Case, iso

SCHEMA = "aletheia-report/1"
TIMELINE_LIMIT = 200


def build_model(
    case: Case,
    profile: ReportProfile,
    *,
    reveal: frozenset[str] = frozenset(),
    now: datetime,
) -> dict[str, Any]:
    """Collect everything a report needs into plain, JSON-serialisable data."""
    verify = case.verify()
    masked_types = set() if profile is ReportProfile.HANDOVER else {t.value for t in PERSONAL_TYPES} - set(reveal)

    def show(itype: str, value: str) -> str:
        return mask_value(itype, value) if itype in masked_types else value

    meta = case.meta()
    indicators = []
    for row in case.list_indicators():
        entry: dict[str, Any] = {"type": row.type, "value": show(row.type, row.value),
                                 "confidence": row.max_confidence, "observations": row.observations,
                                 "evidence_ids": row.evidence_ids}
        if row.type == "url" and row.attrs.get("ig_shortcode"):
            try:
                ig = decode_ig(row.attrs["ig_shortcode"], now=now)
                entry["ig_post_time"] = {"created_at": ig.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                         "plausible": ig.plausible, "method": "heuristic"}
            except Exception:  # noqa: BLE001 - a malformed shortcode must never break a report
                pass
        indicators.append(entry)

    correlation = correlate(case)
    for cluster in correlation["clusters"]:
        for item in cluster["shared"]:
            item["value"] = show(item["type"], item["value"])
    for pair in correlation["cooccurrence"]:
        for side in ("a", "b"):
            pair[side]["value"] = show(pair[side]["type"], pair[side]["value"])

    analyses = case.list_analyses()
    triage = [a for a in analyses if a["kind"] == "triage"]
    if profile is ReportProfile.PUBLICATION:  # matched text may contain personal data
        for a in triage:
            for hit in a["result"].get("hits", []):
                hit["snippet"] = ""
    domains = [a["result"] for a in analyses if a["kind"] == "domain"]
    timeline = []
    for a in analyses:
        if a["kind"] == "timeline" and profile is ReportProfile.HANDOVER:
            timeline.extend(a["result"].get("events", []))
    timeline.sort(key=lambda e: e.get("ts", ""))

    evidence = [{
        "id": e.id, "kind": e.kind, "source": e.source if profile is ReportProfile.HANDOVER or e.kind.startswith("http")
        else "(withheld)", "method": e.method, "exposure": e.exposure, "collected_at": e.collected_at,
        "sha256": e.sha256, "size": e.size, "media_type": e.media_type,
    } for e in case.list_evidence()]

    return {
        "schema": SCHEMA,
        "tool_version": __version__,
        "aup_version": AUP_VERSION,
        "generated_at": iso(now),
        "profile": str(profile),
        "revealed_types": sorted(reveal),
        "case": {"id": case.case_id, "title": meta.get("title", ""), "purpose": meta.get("purpose", ""),
                 "created_at": meta.get("created_at", "")},
        "integrity": {"ok": verify.ok, "audit_head": verify.audit_head, "entries": verify.entries_checked,
                      "issues": [i.code for i in verify.issues if i.severity == "error"]},
        "evidence": evidence,
        "indicators": indicators,
        "correlation": correlation,
        "triage": [{"evidence_id": a["evidence_id"], **a["result"]} for a in triage],
        "domains": domains,
        "timeline": timeline[:TIMELINE_LIMIT],
        "timeline_total": len(timeline),
    }


# --- Markdown --------------------------------------------------------------------------------


def _md(s: Any) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _lab(t: Translator, prefix: str, value: str) -> str:
    """Translated label for a technical token, falling back to the token itself."""
    return t(prefix + value) if t.has(prefix + value) else value


def _lang_expl(explain: dict[str, str], lang: str) -> str:
    key = "el" if lang == "el" else "en"
    return explain.get(key) or explain.get("en") or ""


def render_markdown(model: dict[str, Any], t: Translator) -> str:
    L: list[str] = []
    add = L.append
    case = model["case"]
    add(f"# {t('report.title')}: {_md(case['title'])}")
    add("")
    add(f"> {t('report.disclaimer')}")
    add("")
    add(f"**{t('report.case_id')}:** `{case['id']}`  ")
    add(f"**{t('report.purpose')}:** {t('purpose.' + case['purpose'])}  ")
    add(f"**{t('report.profile')}:** {t('profile.' + model['profile'])}  ")
    add(f"**{t('report.generated')}:** {model['generated_at']}  ")
    add(f"**{t('report.tool')}:** Aletheia {model['tool_version']}")
    add("")
    add(f"## {t('report.integrity')}")
    integ = model["integrity"]
    add(t("report.integrity.ok") if integ["ok"] else t("report.integrity.fail", issues=", ".join(integ["issues"])))
    if integ["audit_head"]:
        add("")
        add(f"{t('report.audit_head')}: `{integ['audit_head']['entry_hash']}` (#{integ['audit_head']['seq']})")
    add("")
    add(t("report.verify_hint"))
    add("")
    add(f"## {t('report.evidence')}")
    add("")
    add(f"| ID | {t('col.kind')} | {t('col.source')} | {t('col.method')} | {t('col.exposure')} | {t('col.collected')} | SHA-256 |")
    add("|---|---|---|---|---|---|---|")
    for e in model["evidence"]:
        add(f"| {e['id']} | {_md(_lab(t, 'kind.', e['kind']))} | {_md(e['source'])} | {_md(_lab(t, 'method.', e['method']))} | {t('exposure.' + e['exposure'])}"
            f" | {e['collected_at']} | `{e['sha256']}` |")
    add("")
    add(f"## {t('report.indicators')}")
    add("")
    if model["indicators"]:
        add(f"| {t('col.type')} | {t('col.value')} | {t('col.confidence')} | {t('col.observations')} | {t('col.evidence')} |")
        add("|---|---|---|---|---|")
        for i in model["indicators"]:
            extra = ""
            if "ig_post_time" in i:
                extra = f" ({t('report.ig_time')}: {i['ig_post_time']['created_at']})"
            add(f"| {i['type']} | `{_md(i['value'])}`{extra} | {t('confidence.' + i['confidence'])} | {i['observations']}"
                f" | {', '.join(i['evidence_ids'])} |")
    else:
        add(t("report.none"))
    add("")
    add(f"## {t('report.correlation')}")
    add("")
    corr = model["correlation"]
    if corr["clusters"]:
        for c in corr["clusters"]:
            add(f"- **{t('report.cluster')} {c['id']}** ({t('confidence.' + c['confidence'])}): {', '.join(c['evidence_ids'])}")
            for s in c["shared"]:
                add(f"  - {s['type']}: `{_md(s['value'])}` ({s['evidence_count']})")
    else:
        add(t("report.none"))
    add("")
    if model["triage"]:
        add(f"## {t('report.triage')}")
        add("")
        add(f"_{t('report.triage.note')}_")
        add("")
        for tr in model["triage"]:
            add(f"- **{tr.get('evidence_id') or '-'}**: {t('level.' + tr['level'])} ({t('report.score')} {tr['score']})")
            for h in tr["hits"][:15]:
                add(f"  - {_md(_lang_expl(h['explain'], t.lang))}")
        add("")
    if model["domains"]:
        add(f"## {t('report.domains')}")
        add("")
        for d in model["domains"]:
            flags = [k for k in ("idn", "mixed_script") if d.get(k)]
            flag_text = ", ".join(t("flag." + f) for f in flags) or "-"
            add(f"- `{_md(d['domain'])}`: {flag_text}")
            for la in d.get("lookalikes", []):
                add(f"  - {t('report.lookalike', brand=_md(la['brand']), official=_md(la['official']), kind=t('lookalike.' + la['kind']))}")
            rd = d.get("rdap")
            if rd and rd.get("found") is False:
                add(f"  - {t('report.rdap.not_found')}")
            elif rd:
                age = d.get("age_days")
                add(f"  - {t('report.rdap.summary', registrar=_md(rd.get('registrar') or '?'), registered=rd.get('registered') or '?')}"
                    + (f" ({t('report.rdap.age', days=age)})" if age is not None else ""))
        add("")
    if model["timeline"]:
        add(f"## {t('report.timeline')}")
        add("")
        for ev in model["timeline"]:
            add(f"- `{ev.get('ts', '?')}` **{_md(ev.get('sender', '?'))}**: {_md(ev.get('snippet', ''))}")
        if model["timeline_total"] > len(model["timeline"]):
            add(f"- … {t('report.timeline.more', n=model['timeline_total'] - len(model['timeline']))}")
        add("")
    add("---")
    add(f"_{t('report.footer', aup=model['aup_version'])}_")
    return "\n".join(L) + "\n"


# --- HTML ------------------------------------------------------------------------------------

_CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--muted:#5b6370;--line:#d9dde3;--accent:#0b5cad;--warn:#8a4b00;--code:#f3f5f8}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e8eaed;--muted:#9aa3af;--line:#2d333b;--accent:#6cb2ff;--warn:#ffb454;--code:#1c2128}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}h1{font-size:1.6rem;margin:.2em 0}h2{font-size:1.2rem;margin:1.8em 0 .5em;border-bottom:1px solid var(--line);padding-bottom:.2em}
.note{border-left:4px solid var(--warn);padding:.6em 1em;background:var(--code);color:var(--fg)}.meta{color:var(--muted)}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border-bottom:1px solid var(--line);padding:.4em .6em;text-align:left;vertical-align:top}
code{background:var(--code);padding:.1em .3em;border-radius:3px;word-break:break-all;font-size:.85em}.bad{color:#c62828;font-weight:600}.ok{color:#2e7d32;font-weight:600}
@media print{body{font-size:11pt}main{max-width:none}a{color:inherit}}
"""


def render_html(model: dict[str, Any], t: Translator) -> str:
    e = lambda v: html.escape(str(v), quote=True)  # noqa: E731
    case = model["case"]
    out: list[str] = []
    add = out.append
    add(f"<!doctype html><html lang=\"{'el' if t.lang == 'el' else 'en'}\"><head><meta charset=\"utf-8\">")
    add("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    add(f"<title>{e(t('report.title'))}: {e(case['title'])}</title><style>{_CSS}</style></head><body><main>")
    add(f"<h1>{e(t('report.title'))}: {e(case['title'])}</h1>")
    add(f"<p class=\"note\">{e(t('report.disclaimer'))}</p>")
    add("<p class=\"meta\">"
        f"{e(t('report.case_id'))}: <code>{e(case['id'])}</code><br>"
        f"{e(t('report.purpose'))}: {e(t('purpose.' + case['purpose']))}<br>"
        f"{e(t('report.profile'))}: {e(t('profile.' + model['profile']))}<br>"
        f"{e(t('report.generated'))}: {e(model['generated_at'])}<br>Aletheia {e(model['tool_version'])}</p>")
    integ = model["integrity"]
    add(f"<h2>{e(t('report.integrity'))}</h2>")
    if integ["ok"]:
        add(f"<p class=\"ok\">{e(t('report.integrity.ok'))}</p>")
    else:
        add(f"<p class=\"bad\">{e(t('report.integrity.fail', issues=', '.join(integ['issues'])))}</p>")
    if integ["audit_head"]:
        add(f"<p>{e(t('report.audit_head'))}: <code>{e(integ['audit_head']['entry_hash'])}</code> (#{e(integ['audit_head']['seq'])})</p>")
    add(f"<p>{e(t('report.verify_hint'))}</p>")
    add(f"<h2>{e(t('report.evidence'))}</h2><div class=\"wrap\"><table><tr><th>ID</th><th>{e(t('col.kind'))}</th>"
        f"<th>{e(t('col.source'))}</th><th>{e(t('col.method'))}</th><th>{e(t('col.exposure'))}</th>"
        f"<th>{e(t('col.collected'))}</th><th>SHA-256</th></tr>")
    for ev in model["evidence"]:
        add(f"<tr><td>{e(ev['id'])}</td><td>{e(_lab(t, 'kind.', ev['kind']))}</td><td>{e(ev['source'])}</td><td>{e(_lab(t, 'method.', ev['method']))}</td>"
            f"<td>{e(t('exposure.' + ev['exposure']))}</td><td>{e(ev['collected_at'])}</td><td><code>{e(ev['sha256'])}</code></td></tr>")
    add("</table></div>")
    add(f"<h2>{e(t('report.indicators'))}</h2>")
    if model["indicators"]:
        add(f"<div class=\"wrap\"><table><tr><th>{e(t('col.type'))}</th><th>{e(t('col.value'))}</th>"
            f"<th>{e(t('col.confidence'))}</th><th>{e(t('col.observations'))}</th><th>{e(t('col.evidence'))}</th></tr>")
        for i in model["indicators"]:
            extra = ""
            if "ig_post_time" in i:
                extra = f" ({e(t('report.ig_time'))}: {e(i['ig_post_time']['created_at'])})"
            add(f"<tr><td>{e(i['type'])}</td><td><code>{e(i['value'])}</code>{extra}</td>"
                f"<td>{e(t('confidence.' + i['confidence']))}</td><td>{e(i['observations'])}</td>"
                f"<td>{e(', '.join(i['evidence_ids']))}</td></tr>")
        add("</table></div>")
    else:
        add(f"<p>{e(t('report.none'))}</p>")
    corr = model["correlation"]
    add(f"<h2>{e(t('report.correlation'))}</h2>")
    if corr["clusters"]:
        add("<ul>")
        for c in corr["clusters"]:
            add(f"<li><strong>{e(t('report.cluster'))} {e(c['id'])}</strong> ({e(t('confidence.' + c['confidence']))}): "
                f"{e(', '.join(c['evidence_ids']))}<ul>")
            for s in c["shared"]:
                add(f"<li>{e(s['type'])}: <code>{e(s['value'])}</code> ({e(s['evidence_count'])})</li>")
            add("</ul></li>")
        add("</ul>")
    else:
        add(f"<p>{e(t('report.none'))}</p>")
    if model["triage"]:
        add(f"<h2>{e(t('report.triage'))}</h2><p class=\"meta\"><em>{e(t('report.triage.note'))}</em></p><ul>")
        for tr in model["triage"]:
            add(f"<li><strong>{e(tr.get('evidence_id') or '-')}</strong>: {e(t('level.' + tr['level']))} "
                f"({e(t('report.score'))} {e(tr['score'])})<ul>")
            for h in tr["hits"][:15]:
                add(f"<li>{e(_lang_expl(h['explain'], t.lang))}</li>")
            add("</ul></li>")
        add("</ul>")
    if model["domains"]:
        add(f"<h2>{e(t('report.domains'))}</h2><ul>")
        for d in model["domains"]:
            flags = [k for k in ("idn", "mixed_script") if d.get(k)]
            add(f"<li><code>{e(d['domain'])}</code>: {e(', '.join(t('flag.' + f) for f in flags) or '-')}<ul>")
            for la in d.get("lookalikes", []):
                add("<li>" + e(t("report.lookalike", brand=la["brand"], official=la["official"],
                                  kind=t("lookalike." + la["kind"]))) + "</li>")
            rd = d.get("rdap")
            if rd and rd.get("found") is False:
                add(f"<li>{e(t('report.rdap.not_found'))}</li>")
            elif rd:
                age = d.get("age_days")
                add("<li>" + e(t("report.rdap.summary", registrar=rd.get("registrar") or "?",
                                 registered=rd.get("registered") or "?"))
                    + (" (" + e(t("report.rdap.age", days=age)) + ")" if age is not None else "") + "</li>")
            add("</ul></li>")
        add("</ul>")
    if model["timeline"]:
        add(f"<h2>{e(t('report.timeline'))}</h2><ul>")
        for ev in model["timeline"]:
            add(f"<li><code>{e(ev.get('ts', '?'))}</code> <strong>{e(ev.get('sender', '?'))}</strong>: {e(ev.get('snippet', ''))}</li>")
        if model["timeline_total"] > len(model["timeline"]):
            add(f"<li>… {e(t('report.timeline.more', n=model['timeline_total'] - len(model['timeline'])))}</li>")
        add("</ul>")
    add(f"<hr><p class=\"meta\"><em>{e(t('report.footer', aup=model['aup_version']))}</em></p></main></body></html>")
    return "".join(out)


def model_json(model: dict[str, Any]) -> str:
    return json.dumps(model, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
