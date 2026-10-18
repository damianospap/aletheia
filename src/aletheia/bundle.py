"""Export a case as a self-verifying bundle (directory or ZIP).

A recipient (police, lawyer, editor) can check integrity *without installing Aletheia*: the bundle
ships ``verify.py`` (standard library only, Python 3.6+) which recomputes every file hash and the
whole audit hash chain, and compares the chain head with the one printed in the report.

Contents::

    manifest.json     case info, evidence list, file hashes, audit head
    audit.jsonl       full hash-chained audit log        (handover profile only)
    evidence/<sha256> the original evidence files        (handover profile only)
    indicators.json   extracted indicators (masked in the publication profile)
    report.json       language-neutral report data
    report.<lang>.md / report.<lang>.html
    VERIFY.txt, verify.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .errors import OutputExistsError, VaultIntegrityError
from .fsutil import atomic_write_bytes, rmtree_force
from .i18n import Translator
from .policy import ReportProfile
from .report import build_model, model_json, render_html, render_markdown
from .vault import Case, canonical_json

VERIFY_SCRIPT = r'''#!/usr/bin/env python3
"""Standalone verifier for an Aletheia evidence bundle (Python 3.6+, standard library only).

Usage:  python3 verify.py [BUNDLE_DIR_OR_ZIP]      (default: the folder containing this script)
Exit status: 0 = everything verified, 1 = problems found, 2 = cannot read the bundle.
"""
import hashlib
import json
import os
import sys
import zipfile

GENESIS = "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class Source:
    def __init__(self, path):
        self.zip = zipfile.ZipFile(path) if os.path.isfile(path) else None
        self.root = path

    def exists(self, name):
        if self.zip:
            return name in self.zip.namelist()
        return os.path.isfile(os.path.join(self.root, *name.split("/")))

    def open(self, name):
        if self.zip:
            return self.zip.open(name)
        return open(os.path.join(self.root, *name.split("/")), "rb")


def sha256_of(fh):
    h = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        h.update(chunk)
        size += len(chunk)
    return h.hexdigest(), size


def main(argv):
    target = argv[1] if len(argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    try:
        src = Source(target)
        with src.open("manifest.json") as fh:
            manifest = json.loads(fh.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        print("CANNOT READ BUNDLE: %s" % exc)
        return 2
    problems = []
    checked = 0
    for name, expected in sorted(manifest.get("files", {}).items()):
        if not src.exists(name):
            problems.append("missing file: " + name)
            continue
        with src.open(name) as fh:
            digest, _ = sha256_of(fh)
        checked += 1
        if digest != expected:
            problems.append("hash mismatch: " + name)
    for ev in manifest.get("evidence", []):
        if not ev.get("included"):
            continue
        name = "evidence/" + ev["sha256"]
        if not src.exists(name):
            problems.append("missing evidence file for " + ev["id"])
            continue
        with src.open(name) as fh:
            digest, size = sha256_of(fh)
        checked += 1
        if digest != ev["sha256"] or size != ev["size"]:
            problems.append("evidence file does not match its hash: " + ev["id"])
    entries = 0
    if manifest.get("audit_included"):
        prev = GENESIS
        head = None
        try:
            with src.open("audit.jsonl") as fh:
                lines = [ln for ln in fh.read().decode("utf-8").splitlines() if ln.strip()]
        except Exception:  # noqa: BLE001
            lines = []
            problems.append("audit.jsonl is missing")
        for n, line in enumerate(lines, 1):
            e = json.loads(line)
            entries += 1
            if e["seq"] != n:
                problems.append("audit sequence gap at entry %d" % n)
            if e["prev_hash"] != prev:
                problems.append("audit chain broken at entry %d" % e["seq"])
            body = {k: e[k] for k in ("seq", "ts", "actor", "action", "payload")}
            calc = hashlib.sha256(prev.encode("ascii") + b"\n" + canonical(body)).hexdigest()
            if calc != e["entry_hash"]:
                problems.append("audit entry modified: %d" % e["seq"])
            prev = e["entry_hash"]
            head = {"seq": e["seq"], "entry_hash": e["entry_hash"]}
        declared = manifest.get("audit_head")
        if declared and (head is None or head["entry_hash"] != declared["entry_hash"]):
            problems.append("audit head does not match the manifest")
    print("Files checked: %d, audit entries checked: %d" % (checked, entries))
    if manifest.get("audit_head"):
        print("Audit head: %s (#%s)" % (manifest["audit_head"]["entry_hash"], manifest["audit_head"]["seq"]))
    if problems:
        print("VERIFICATION FAILED")
        for p in problems:
            print(" - " + p)
        return 1
    print("VERIFICATION OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


def _copy_verified(src: Path, dst: Path, expected_sha: str) -> None:
    h = hashlib.sha256()
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for chunk in iter(lambda: fin.read(1 << 20), b""):
            h.update(chunk)
            fout.write(chunk)
    if h.hexdigest() != expected_sha:
        raise VaultIntegrityError(detail=f"evidence file {expected_sha[:12]} does not match its hash")


def _write_zip(staging: Path, dest: Path) -> None:
    tmp = dest.with_name(f".{dest.name}.part")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(p for p in staging.rglob("*") if p.is_file()):
            info = zipfile.ZipInfo(path.relative_to(staging).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(path, "rb") as fin, zf.open(info, "w") as fout:
                shutil.copyfileobj(fin, fout, 1 << 20)
    os.replace(tmp, dest)


def export_bundle(
    case: Case,
    dest: Path,
    *,
    profile: ReportProfile,
    langs: Sequence[str],
    now: datetime,
    reveal: frozenset[str] = frozenset(),
    as_zip: bool = False,
    force: bool = False,
) -> tuple[Path, dict[str, Any]]:
    dest = Path(dest)
    if dest.exists():
        if not force:
            raise OutputExistsError(path=str(dest))
        if dest.is_dir():
            rmtree_force(dest)
        else:
            dest.unlink()
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".aletheia-export-", dir=dest.parent))
    try:
        full = profile is ReportProfile.HANDOVER
        model = build_model(case, profile, reveal=reveal, now=now)
        files: dict[str, str] = {}

        def put(name: str, data: bytes) -> None:
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(path, data, mode=0o644)
            files[name] = hashlib.sha256(data).hexdigest()

        put("report.json", model_json(model).encode("utf-8"))
        put("indicators.json", (json.dumps(model["indicators"], indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))
        for lang in langs:
            t = Translator(lang)
            tag = "el" if t.lang == "el" else "en"
            put(f"report.{tag}.md", render_markdown(model, t).encode("utf-8"))
            put(f"report.{tag}.html", render_html(model, t).encode("utf-8"))
        put("VERIFY.txt", "\n\n".join(Translator(lang)("bundle.verify_text") for lang in langs).encode("utf-8") + b"\n")
        put("verify.py", VERIFY_SCRIPT.encode("utf-8"))

        if full:
            lines = [canonical_json({"seq": e.seq, "ts": e.ts, "actor": e.actor, "action": e.action,
                                     "payload": e.payload, "prev_hash": e.prev_hash, "entry_hash": e.entry_hash}).decode("ascii")
                     for e in case.audit_entries()]
            put("audit.jsonl", ("\n".join(lines) + "\n").encode("ascii"))

        evidence_manifest = []
        for ev in case.list_evidence():
            if full:
                target = staging / "evidence" / ev.sha256
                if not target.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    _copy_verified(case.blob_path(ev.sha256), target, ev.sha256)
                    os.chmod(target, 0o644)
            evidence_manifest.append({
                "id": ev.id, "kind": ev.kind, "sha256": ev.sha256, "size": ev.size, "media_type": ev.media_type,
                "source": ev.source if full else None, "method": ev.method, "exposure": ev.exposure,
                "collected_at": ev.collected_at, "included": full,
            })
        manifest = {
            "format": "aletheia-bundle/1",
            "tool_version": __version__,
            "generated_at": model["generated_at"],
            "profile": str(profile),
            "case": model["case"],
            "audit_included": full,
            "audit_head": model["integrity"]["audit_head"],
            "integrity_ok": model["integrity"]["ok"],
            "evidence": evidence_manifest,
            "files": dict(sorted(files.items())),
        }
        atomic_write_bytes(staging / "manifest.json", (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"), mode=0o644)
        if as_zip:
            _write_zip(staging, dest)
            rmtree_force(staging)
        else:
            os.replace(staging, dest)
        return dest, manifest
    except BaseException:
        if staging.exists():
            rmtree_force(staging)
        raise
