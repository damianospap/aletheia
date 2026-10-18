"""Command-line interface.

Design rules: every message is translated (en-US / el); ``--json`` gives stable, language-neutral
machine output; errors print one line with a stable code and map to documented exit codes;
anything that touches the network or the target is opt-in and explicit.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import traceback
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from . import AUP_VERSION, __version__
from .bundle import export_bundle
from .capture import capture_url
from .correlate import correlate, edges_csv
from .domains import analyze_domain
from .errors import (
    EXIT_OK,
    AletheiaError,
    InputTooLargeError,
    InternalError,
    UsageError,
    ValidationError,
)
from .http import HttpClient, HttpPolicy
from .i18n import SUPPORTED, Translator, detect_lang
from .ig_ids import decode as decode_ig
from .indexing import index_evidence, is_texty
from .indicators import EXTRACTOR_VERSION, context_for, extract_indicators
from .indicators.urls import classify_instagram, parse_url
from .meta_export import ExportSource, iter_threads
from .models import Exposure, IndicatorType, Purpose
from .platform_info import ensure_home, get_platform_info, is_shared_storage, probe_filesystem, resolve_home
from .policy import AUP_KEYS, ReportProfile
from .rdap import RdapClient, domain_age_days
from .textnorm import MAX_TEXT_BYTES, decode_text
from .triage import load_pack_file, load_default_packs, triage as run_triage
from .vault import Case, Vault, utc_now

_PERSONAL = {t.value for t in (IndicatorType.EMAIL, IndicatorType.PHONE, IndicatorType.IBAN, IndicatorType.HANDLE)}


@dataclass
class Ctx:
    t: Translator
    out: Any
    err: Any
    stdin: Any
    json_mode: bool
    debug: bool
    home: Path
    vault: Vault
    now: Callable[[], datetime]
    client_factory: Callable[[], HttpClient]
    env: Mapping[str, str]

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def emit(self, data: dict[str, Any], human: str) -> None:
        if self.json_mode:
            print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False), file=self.out)
        else:
            print(human, file=self.out)


# --- helpers ---------------------------------------------------------------------------------


def configure_stdio() -> None:
    """Make piped output UTF-8 (Windows pipes default to the legacy ANSI code page)."""
    for stream in (sys.stdout, sys.stderr):
        enc = (getattr(stream, "encoding", "") or "").lower().replace("-", "").replace("_", "")
        console = sys.platform == "win32" and getattr(stream, "isatty", lambda: False)()
        if enc != "utf8" and not console and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _read_stdin_bytes(ctx: Ctx, limit: int) -> bytes:
    buf = getattr(ctx.stdin, "buffer", ctx.stdin)
    data = buf.read(limit + 1)
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > limit:
        raise InputTooLargeError(size=len(data), limit=limit)
    return data


def _input_source(args: argparse.Namespace) -> tuple[str, str | None]:
    chosen = [k for k in ("text", "file", "stdin") if getattr(args, k, None)]
    if len(chosen) != 1:
        raise UsageError(key="error.cli.input_required")
    return chosen[0], getattr(args, chosen[0])


def _read_file(path: str, limit: int) -> bytes:
    p = Path(path)
    if not p.is_file():
        raise UsageError(key="error.cli.file_not_found", path=path)
    if p.stat().st_size > limit:
        raise InputTooLargeError(size=p.stat().st_size, limit=limit)
    try:
        return p.read_bytes()
    except OSError as exc:
        raise UsageError(key="error.cli.unreadable", path=path, detail=exc.strerror or str(exc)) from exc


def _open_case(ctx: Ctx, case_id: str) -> Case:
    return ctx.vault.open_case(case_id, actor=ctx.env.get("ALETHEIA_ACTOR"))


def _case_text_evidence(case: Case, only: str | None) -> list[tuple[Any, str]]:
    items = [case.get_evidence(only)] if only else case.list_evidence()
    out = []
    for ev in items:
        if ev.kind in ("text", "ig_thread", "http_body", "file") and is_texty(ev.media_type, ev.kind):
            text, _enc, _lossy = decode_text(case.read_blob(ev.sha256))
            out.append((ev, text))
    return out


# --- commands --------------------------------------------------------------------------------


def cmd_doctor(ctx: Ctx, args: argparse.Namespace) -> int:
    t = ctx.t
    info = get_platform_info()
    problems: list[str] = []
    caps = None
    shared = is_shared_storage(ctx.home, info.system)
    if shared:
        problems.append("doctor.problem.shared_storage")
    else:
        ensure_home(ctx.home, info.system)
        caps = probe_filesystem(ctx.home, info.system)
        problems += caps.problems
    data = {"version": __version__, "platform": info.__dict__, "lang": t.lang, "home": str(ctx.home),
            "filesystem": caps.to_dict() if caps else None, "problems": problems, "ok": not problems}
    lines = [f"Aletheia {__version__}",
             t("doctor.platform", system=info.system, machine=info.machine, release=info.release),
             t("doctor.python", python=info.python), t("doctor.lang", lang=t.lang),
             t("doctor.home", path=ctx.home), t("doctor.encoding", enc=info.stdout_encoding)]
    if caps:
        lines.append(t("doctor.fs"))
        for name in ("atomic_replace", "fsync", "locking", "private_mode", "symlinks", "exec_bit", "case_sensitive",
                     "unicode_names", "long_paths"):
            mark = "[+]" if getattr(caps, name) else "[-]"
            lines.append(f"  {mark} {t('doctor.feature.' + name)}")
        if caps.free_bytes is not None:
            lines.append(t("doctor.free", mb=caps.free_bytes // (1024 * 1024)))
    if problems:
        lines.append(t("doctor.problems"))
        lines += [f"  - {t(p)}" for p in problems]
    else:
        lines.append(t("doctor.ok"))
    ctx.emit(data, "\n".join(lines))
    return EXIT_OK if not problems else 1


def cmd_aup(ctx: Ctx, args: argparse.Namespace) -> int:
    items = [ctx.t(k) for k in AUP_KEYS]
    ctx.emit({"aup_version": AUP_VERSION, "items": items},
             ctx.t("msg.aup_header", version=AUP_VERSION) + "\n" + "\n".join(f"  {i}. {txt}" for i, txt in enumerate(items, 1)))
    return EXIT_OK


def cmd_case_new(ctx: Ctx, args: argparse.Namespace) -> int:
    ensure_home(ctx.home)
    if not args.accept_aup and not ctx.json_mode:
        ctx.say(ctx.t("msg.aup_header", version=AUP_VERSION))
        for i, key in enumerate(AUP_KEYS, 1):
            ctx.say(f"  {i}. {ctx.t(key)}")
    case = ctx.vault.create_case(args.title, Purpose(args.purpose), accept_aup=args.accept_aup, actor=args.actor)
    with case:
        ctx.emit({"case_id": case.case_id, "title": args.title, "purpose": args.purpose},
                 ctx.t("msg.case_created", case_id=case.case_id))
    return EXIT_OK


def cmd_case_list(ctx: Ctx, args: argparse.Namespace) -> int:
    cases = ctx.vault.list_cases()
    data = {"cases": [c.__dict__ for c in cases]}
    if not cases:
        ctx.emit(data, ctx.t("msg.no_cases"))
    else:
        ctx.emit(data, "\n".join(f"{c.case_id}  {c.created_at[:10]}  {ctx.t('purpose.' + c.purpose)}  "
                                 f"[{c.evidence_count}]  {c.title}" for c in cases))
    return EXIT_OK


def cmd_case_show(ctx: Ctx, args: argparse.Namespace) -> int:
    with _open_case(ctx, args.case) as case:
        meta = case.meta()
        evidence = case.list_evidence()
        head = case.anchor()
        data = {"case": meta, "evidence": len(evidence), "indicators": len(case.list_indicators()), "audit_head": head}
        ctx.emit(data, "\n".join([
            f"{ctx.t('report.case_id')}: {meta.get('case_id')}", f"{ctx.t('report.title')}: {meta.get('title')}",
            f"{ctx.t('report.purpose')}: {ctx.t('purpose.' + meta.get('purpose', 'journalism'))}",
            f"{ctx.t('report.generated')}: {meta.get('created_at')}",
            ctx.t("msg.case_counts", evidence=len(evidence), indicators=data["indicators"]),
            f"{ctx.t('report.audit_head')}: {head['entry_hash'] if head else '-'}"]))
    return EXIT_OK


def cmd_case_verify(ctx: Ctx, args: argparse.Namespace) -> int:
    with _open_case(ctx, args.case) as case:
        rep = case.verify()
    errors = [i for i in rep.issues if i.severity == "error"]
    lines = []
    if rep.ok:
        lines.append(ctx.t("msg.verify.ok", entries=rep.entries_checked, evidence=rep.evidence_checked))
    else:
        lines.append(ctx.t("msg.verify.fail", count=len(errors)))
    lines += [f"  - {i.code}: {i.detail}" + (" (warning)" if i.severity == "warning" else "") for i in rep.issues]
    ctx.emit(rep.to_dict(), "\n".join(lines))
    return EXIT_OK if rep.ok else 4


def cmd_case_export(ctx: Ctx, args: argparse.Namespace) -> int:
    profile = ReportProfile(args.profile)
    reveal = frozenset(x.strip() for x in (args.reveal or "").split(",") if x.strip())
    bad = reveal - _PERSONAL
    if bad:
        raise UsageError(key="error.cli.bad_reveal", types=", ".join(sorted(bad)))
    if reveal and profile is not ReportProfile.PUBLICATION:
        raise UsageError(key="error.cli.reveal_needs_publication")
    langs = ["en-US", "el"] if args.report_lang == "both" else ["el" if args.report_lang == "el" else "en-US"]
    with _open_case(ctx, args.case) as case:
        if reveal:
            ctx.say(ctx.t("msg.reveal_warning", types=", ".join(sorted(reveal))))
            case.log("report.reveal", {"types": sorted(reveal), "profile": str(profile)})
        path, manifest = export_bundle(case, Path(args.out), profile=profile, langs=langs, now=ctx.now(),
                                       reveal=reveal, as_zip=args.zip, force=args.force)
    ctx.emit({"path": str(path), "profile": str(profile), "files": len(manifest["files"]),
              "integrity_ok": manifest["integrity_ok"], "audit_head": manifest["audit_head"]},
             ctx.t("msg.export.done", path=path))
    return EXIT_OK


def cmd_case_delete(ctx: Ctx, args: argparse.Namespace) -> int:
    if not args.yes:
        raise UsageError(key="error.cli.confirm_delete")
    ctx.vault.delete_case(args.case)
    ctx.emit({"deleted": args.case}, ctx.t("msg.deleted", case_id=args.case))
    return EXIT_OK


def cmd_add(ctx: Ctx, args: argparse.Namespace) -> int:
    which, value = _input_source(args)
    with _open_case(ctx, args.case) as case:
        if which == "file":
            p = Path(value or "")
            if not p.is_file():
                raise UsageError(key="error.cli.file_not_found", path=str(p))
            media = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
            rec = case.add_evidence_file(p, kind="file", source=args.source or p.name, method="manual_import",
                                         media_type=media, note=args.note)
        else:
            data = (value or "").encode("utf-8") if which == "text" else _read_stdin_bytes(ctx, MAX_TEXT_BYTES)
            if not data:
                raise UsageError(key="error.cli.stdin_empty")
            rec = case.add_evidence(data, kind="text", source=args.source or which, method="manual_import",
                                    media_type="text/plain", note=args.note)
        n = index_evidence(case, rec.id)
    ctx.emit({"evidence": rec.__dict__, "indicators_recorded": n},
             ctx.t("msg.evidence_added", id=rec.id, size=rec.size, sha=rec.sha256[:16]) + "\n" + ctx.t.plural("msg.indicators_found", n))
    return EXIT_OK


def cmd_extract(ctx: Ctx, args: argparse.Namespace) -> int:
    which, value = _input_source(args)
    if which == "text":
        raw = (value or "").encode("utf-8")
    elif which == "file":
        raw = _read_file(value or "", MAX_TEXT_BYTES)
    else:
        raw = _read_stdin_bytes(ctx, MAX_TEXT_BYTES)
    text, _enc, _lossy = decode_text(raw)
    matches = [m for m in extract_indicators(text)]
    data = {"extractor_version": EXTRACTOR_VERSION, "indicators": [
        {"type": str(m.type), "value": m.value, "raw": m.raw, "start": m.start, "end": m.end,
         "confidence": str(m.confidence), "derived": m.derived, "attrs": m.attrs} for m in matches]}
    if not matches:
        ctx.emit(data, ctx.t("msg.extract.none"))
    else:
        ctx.emit(data, "\n".join(f"{m.type:<7} {ctx.t('confidence.' + str(m.confidence)):<8} {m.value}"
                                 + (f"  ({ctx.t('msg.derived')})" if m.derived else "") for m in matches))
    return EXIT_OK


def cmd_triage(ctx: Ctx, args: argparse.Namespace) -> int:
    packs = load_default_packs()
    if args.pack:
        packs.append(load_pack_file(Path(args.pack)))
    results = []
    if args.case:
        with _open_case(ctx, args.case) as case:
            for ev, text in _case_text_evidence(case, args.evidence):
                res = run_triage(text, packs)
                case.save_analysis("triage", ev.id, res.to_dict())
                results.append((ev.id, res))
    else:
        which, value = _input_source(args)
        raw = (value or "").encode("utf-8") if which == "text" else (
            _read_file(value or "", MAX_TEXT_BYTES) if which == "file" else _read_stdin_bytes(ctx, MAX_TEXT_BYTES))
        results.append((None, run_triage(decode_text(raw)[0], packs)))
    lines = []
    for ev_id, res in results:
        lines.append(f"{ev_id or '-'}: " + ctx.t("msg.triage.result", level=ctx.t("level." + res.level), score=res.score))
        for h in res.hits[:10]:
            expl = h.explain.get("el" if ctx.t.lang == "el" else "en") or h.explain.get("en", "")
            lines.append(f"  - {expl}")
    if not results:
        lines.append(ctx.t("msg.triage.nothing"))
    ctx.emit({"results": [{"evidence_id": e, **r.to_dict()} for e, r in results]}, "\n".join(lines))
    return EXIT_OK


def cmd_ig_export(ctx: Ctx, args: argparse.Namespace) -> int:
    total_threads = total_messages = 0
    with _open_case(ctx, args.case) as case, ExportSource(Path(args.path)) as source:
        container = source.sha256_of_container()
        for thread in iter_threads(source):
            raw_ids = []
            for name, data in thread.raw_members:
                rec = case.add_evidence(data, kind="ig_export_json", source=f"ig-export:{name}",
                                        method="manual_import", media_type="application/json",
                                        meta={"container_sha256": container})
                raw_ids.append(rec.id)
            transcript = thread.transcript()
            rec = case.add_evidence(
                transcript.encode("utf-8"), kind="ig_thread", source=f"ig-export:{thread.folder}",
                method="manual_import", media_type="text/plain",
                meta={"folder": thread.folder, "title": thread.title, "participants": thread.participants,
                      "messages": len(thread.messages), "derived_from": raw_ids, "container_sha256": container},
            )
            index_evidence(case, rec.id)
            events = []
            for m in thread.messages:
                text = " ".join([m.text, *m.links])
                found = [x for x in extract_indicators(text) if not x.derived and str(x.type) in
                         {"iban", "wallet", "phone", "email", "url"}]
                if found and len(events) < 500:
                    events.append({"ts": m.iso, "sender": m.sender, "snippet": m.text[:200],
                                   "indicators": sorted({f"{x.type}:{x.value}" for x in found})})
            case.save_analysis("timeline", rec.id, {"thread": thread.folder, "events": events})
            total_threads += 1
            total_messages += len(thread.messages)
    ctx.emit({"threads": total_threads, "messages": total_messages},
             ctx.t("msg.ig.threads", threads=total_threads, messages=total_messages))
    return EXIT_OK


def cmd_ig_id(ctx: Ctx, args: argparse.Namespace) -> int:
    code = args.shortcode.strip()
    if "://" in code or "instagram.com" in code:
        ig = classify_instagram(parse_url(code if "://" in code else "https://" + code))
        if not ig or not ig.shortcode:
            raise ValidationError(key="error.validation.no_shortcode")
        code = ig.shortcode
    res = decode_ig(code, now=ctx.now())
    data = {"shortcode": code, "media_id": res.media_id, "created_at": res.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "shard": res.shard, "sequence": res.sequence, "plausible": res.plausible, "method": "heuristic"}
    human = ctx.t("msg.ig.decoded", shortcode=code, media_id=res.media_id, created=data["created_at"],
                  shard=res.shard, sequence=res.sequence)
    if not res.plausible:
        human += "\n" + ctx.t("msg.ig.implausible")
    ctx.emit(data, human)
    return EXIT_OK


def cmd_domain(ctx: Ctx, args: argparse.Namespace) -> int:
    signals = analyze_domain(args.domain)
    result: dict[str, Any] = signals.to_dict()
    result.update({"rdap": None, "age_days": None})
    evidence_id = None
    with _open_case(ctx, args.case) as case:
        if not args.offline:
            rdap = RdapClient(ctx.client_factory(), cache_dir=ctx.home / "cache", clock=ctx.now)
            info, raw = rdap.lookup(args.domain)
            rec = case.add_evidence(raw, kind="rdap", source=info.source_url or args.domain, method="rdap",
                                    exposure=Exposure.PASSIVE, media_type="application/rdap+json")
            evidence_id = rec.id
            result["rdap"] = info.to_dict()
            result["age_days"] = domain_age_days(info, ctx.now())
        case.save_analysis("domain", evidence_id, result)
    lines = [f"{signals.domain} ({signals.unicode})"]
    for flag in ("idn", "mixed_script"):
        if getattr(signals, flag):
            lines.append(f"  - {ctx.t('flag.' + flag)}")
    for la in signals.lookalikes:
        lines.append("  - " + ctx.t("report.lookalike", brand=la["brand"], official=la["official"],
                                    kind=ctx.t("lookalike." + la["kind"])))
    rd = result["rdap"]
    if rd and rd.get("found") is False:
        lines.append("  - " + ctx.t("report.rdap.not_found"))
    elif rd:
        age = result["age_days"]
        lines.append("  - " + ctx.t("report.rdap.summary", registrar=rd.get("registrar") or "?",
                                    registered=rd.get("registered") or "?")
                     + (f" ({ctx.t('report.rdap.age', days=age)})" if age is not None else ""))
    ctx.emit(result, "\n".join(lines))
    return EXIT_OK


def cmd_capture(ctx: Ctx, args: argparse.Namespace) -> int:
    host = parse_url(args.url).host
    if not ctx.json_mode and args.confirm_active:
        ctx.say(ctx.t("msg.capture.active_notice", host=host))
    with _open_case(ctx, args.case) as case:
        out = capture_url(case, args.url, ctx.client_factory(), confirm_active=args.confirm_active,
                          ignore_robots=args.ignore_robots, allow_invalid_tls=args.allow_invalid_tls,
                          user_agent=args.user_agent)
    human = ctx.t("msg.capture.done", url=out.final_url, status=out.status, body=out.body.id, meta=out.meta.id)
    if not out.tls_verified:
        human += "\n" + ctx.t("msg.capture.tls_unverified")
    ctx.emit({"final_url": out.final_url, "status": out.status, "body_evidence": out.body.id,
              "meta_evidence": out.meta.id, "tls_verified": out.tls_verified, "indicators_recorded": out.indicators}, human)
    return EXIT_OK


def cmd_correlate(ctx: Ctx, args: argparse.Namespace) -> int:
    with _open_case(ctx, args.case) as case:
        result = correlate(case)
        if args.format == "csv":
            print(edges_csv(case, result), end="", file=ctx.out)
            return EXIT_OK
    if args.format == "json" or ctx.json_mode:
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False), file=ctx.out)
        return EXIT_OK
    if not result["clusters"] and not result["cooccurrence"]:
        ctx.say(ctx.t("msg.correlate.none"))
        return EXIT_OK
    for c in result["clusters"]:
        ctx.say(f"{ctx.t('report.cluster')} {c['id']} ({ctx.t('confidence.' + c['confidence'])}): {', '.join(c['evidence_ids'])}")
        for s in c["shared"]:
            ctx.say(f"  {s['type']}: {s['value']} ({s['evidence_count']})")
    for p in result["cooccurrence"]:
        ctx.say(ctx.t("msg.correlate.cooccur", a=p["a"]["value"], b=p["b"]["value"], evidence=", ".join(p["evidence_ids"])))
    return EXIT_OK


# --- parser ----------------------------------------------------------------------------------


def _input_flags(sub: argparse.ArgumentParser, t: Translator) -> None:
    sub.add_argument("--text", help=t("help.opt.text"))
    sub.add_argument("--file", help=t("help.opt.file"))
    sub.add_argument("--stdin", action="store_true", help=t("help.opt.stdin"))


def build_parser(t: Translator, err: Any = None) -> argparse.ArgumentParser:
    stream = err or sys.stderr

    class _Parser(argparse.ArgumentParser):
        """argparse with a translated error prefix and hint (argparse's own wording stays English)."""

        def error(self, message: str) -> "NoReturn":  # type: ignore[override]
            self.print_usage(stream)
            print(f"{t('error.prefix')}: {message}\n{t('error.cli.see_help')}", file=stream)
            raise SystemExit(2)

    p = _Parser(prog="aletheia", description=t("help.description"))
    p.add_argument("--version", action="version", version=f"aletheia {__version__}")
    p.add_argument("--home", help=t("help.opt.home"))
    p.add_argument("--lang", choices=["en", "el"], help=t("help.opt.lang"))
    p.add_argument("--json", action="store_true", help=t("help.opt.json"))
    p.add_argument("--debug", action="store_true", help=t("help.opt.debug"))
    sp = p.add_subparsers(dest="command", metavar="COMMAND")

    sp.add_parser("doctor", help=t("help.cmd.doctor")).set_defaults(func=cmd_doctor)
    sp.add_parser("aup", help=t("help.cmd.aup")).set_defaults(func=cmd_aup)

    case = sp.add_parser("case", help=t("help.cmd.case"))
    cs = case.add_subparsers(dest="case_command", metavar="ACTION", required=True)
    n = cs.add_parser("new", help=t("help.case.new"))
    n.add_argument("--title", required=True, help=t("help.opt.title"))
    n.add_argument("--purpose", required=True, choices=[x.value for x in Purpose], help=t("help.opt.purpose"))
    n.add_argument("--accept-aup", action="store_true", help=t("help.opt.accept_aup"))
    n.add_argument("--actor", help=t("help.opt.actor"))
    n.set_defaults(func=cmd_case_new)
    cs.add_parser("list", help=t("help.case.list")).set_defaults(func=cmd_case_list)
    for name, fn, key in (("show", cmd_case_show, "help.case.show"), ("verify", cmd_case_verify, "help.case.verify")):
        s = cs.add_parser(name, help=t(key))
        s.add_argument("case", help=t("help.arg.case"))
        s.set_defaults(func=fn)
    e = cs.add_parser("export", help=t("help.case.export"))
    e.add_argument("case", help=t("help.arg.case"))
    e.add_argument("--out", required=True, help=t("help.opt.out"))
    e.add_argument("--profile", choices=[x.value for x in ReportProfile], default="handover", help=t("help.opt.profile"))
    e.add_argument("--report-lang", choices=["en", "el", "both"], default="both", help=t("help.opt.report_lang"))
    e.add_argument("--zip", action="store_true", help=t("help.opt.zip"))
    e.add_argument("--force", action="store_true", help=t("help.opt.force"))
    e.add_argument("--reveal", help=t("help.opt.reveal"))
    e.set_defaults(func=cmd_case_export)
    d = cs.add_parser("delete", help=t("help.case.delete"))
    d.add_argument("case", help=t("help.arg.case"))
    d.add_argument("--yes", action="store_true", help=t("help.opt.yes"))
    d.set_defaults(func=cmd_case_delete)

    a = sp.add_parser("add", help=t("help.cmd.add"))
    a.add_argument("case", help=t("help.arg.case"))
    _input_flags(a, t)
    a.add_argument("--source", help=t("help.opt.source"))
    a.add_argument("--note", help=t("help.opt.note"))
    a.set_defaults(func=cmd_add)

    x = sp.add_parser("extract", help=t("help.cmd.extract"))
    _input_flags(x, t)
    x.set_defaults(func=cmd_extract)

    tr = sp.add_parser("triage", help=t("help.cmd.triage"))
    tr.add_argument("--case", help=t("help.arg.case"))
    tr.add_argument("--evidence", help=t("help.opt.evidence"))
    tr.add_argument("--pack", help=t("help.opt.pack"))
    _input_flags(tr, t)
    tr.set_defaults(func=cmd_triage)

    ig = sp.add_parser("ig-export", help=t("help.cmd.ig_export"))
    ig.add_argument("case", help=t("help.arg.case"))
    ig.add_argument("path", help=t("help.arg.path"))
    ig.set_defaults(func=cmd_ig_export)

    igid = sp.add_parser("ig-id", help=t("help.cmd.ig_id"))
    igid.add_argument("shortcode", help=t("help.arg.shortcode"))
    igid.set_defaults(func=cmd_ig_id)

    dm = sp.add_parser("domain", help=t("help.cmd.domain"))
    dm.add_argument("case", help=t("help.arg.case"))
    dm.add_argument("domain", help=t("help.arg.domain"))
    dm.add_argument("--offline", action="store_true", help=t("help.opt.offline"))
    dm.set_defaults(func=cmd_domain)

    cp = sp.add_parser("capture", help=t("help.cmd.capture"))
    cp.add_argument("case", help=t("help.arg.case"))
    cp.add_argument("url", help=t("help.arg.url"))
    cp.add_argument("--confirm-active", action="store_true", help=t("help.opt.confirm_active"))
    cp.add_argument("--ignore-robots", action="store_true", help=t("help.opt.ignore_robots"))
    cp.add_argument("--allow-invalid-tls", action="store_true", help=t("help.opt.allow_invalid_tls"))
    cp.add_argument("--user-agent", help=t("help.opt.user_agent"))
    cp.set_defaults(func=cmd_capture)

    co = sp.add_parser("correlate", help=t("help.cmd.correlate"))
    co.add_argument("case", help=t("help.arg.case"))
    co.add_argument("--format", choices=["text", "json", "csv"], default="text", help=t("help.opt.format"))
    co.set_defaults(func=cmd_correlate)
    return p


# --- entry point -----------------------------------------------------------------------------


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    env: Mapping[str, str] | None = None,
    now: Callable[[], datetime] = utc_now,
    client_factory: Callable[[], HttpClient] | None = None,
) -> int:
    """Run the CLI and return the process exit code (never calls ``sys.exit``)."""
    env = os.environ if env is None else env
    argv = list(sys.argv[1:] if argv is None else argv)
    if stdout is None and stderr is None:
        configure_stdio()
    out, err = stdout or sys.stdout, stderr or sys.stderr
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang")
    pre_ns, _ = pre.parse_known_args(argv)
    t = Translator(detect_lang(pre_ns.lang, env))
    parser = build_parser(t, err)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed help/usage/error
        return int(exc.code) if isinstance(exc.code, int) else 2
    if not getattr(args, "func", None):
        parser.print_help(out)
        return 2
    home = resolve_home(args.home, env)
    ctx = Ctx(t=t, out=out, err=err, stdin=stdin or sys.stdin, json_mode=args.json, debug=args.debug, home=home,
              vault=Vault(home, clock=now, actor=env.get("ALETHEIA_ACTOR") or "operator"), now=now,
              client_factory=client_factory or (lambda: HttpClient(HttpPolicy())), env=env)
    try:
        return int(args.func(ctx, args))
    except AletheiaError as exc:
        message = exc.localized(t)
        if args.json:
            print(json.dumps({"error": {"code": exc.code, "message": message}}, ensure_ascii=False), file=err)
        else:
            print(f"{t('error.prefix')} [{exc.code}]: {message}", file=err)
        if args.debug:
            traceback.print_exc(file=err)
        return exc.exit_code
    except BrokenPipeError:
        return EXIT_OK
    except KeyboardInterrupt:
        print(t("error.interrupted"), file=err)
        return 130
    except Exception as exc:  # noqa: BLE001 - last-resort boundary: never show a raw traceback by default
        wrapped = InternalError(kind=exc.__class__.__name__)
        print(f"{t('error.prefix')} [{wrapped.code}]: {wrapped.localized(t)}", file=err)
        if args.debug:
            traceback.print_exc(file=err)
        return wrapped.exit_code
