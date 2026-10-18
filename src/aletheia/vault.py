"""The case vault: tamper-evident, local-only evidence storage.

Layout (one directory per case, so a case can be exported or destroyed on its own)::

    <home>/cases/<case_id>/
        case.db         SQLite: meta, audit, evidence, indicator, observation, analysis
        blobs/ab/<sha>  immutable, content-addressed evidence files (read-only mode)
        .lock           advisory lock for writers

Integrity model:

* Every state-changing action appends an entry to a SHA-256 *hash chain* (each entry commits to
  its predecessor). Evidence rows and analysis results are cross-checked against that chain.
* ``verify()`` re-derives everything and reports *all* problems rather than stopping at the first.
* The chain proves consistency, not authenticity: someone with full write access can rebuild it.
  Publish or timestamp the *head hash* (``anchor()``) somewhere outside the vault to fix this.

There is no encryption at rest in this version; use full-disk encryption (see docs/THREAT_MODEL.md).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import AUP_VERSION, __version__
from .errors import (
    CaseNotFoundError,
    InputTooLargeError,
    InvalidCaseIdError,
    ValidationError,
    VaultError,
    VaultIntegrityError,
    VaultLockedError,
    VaultTooNewError,
)
from .fsutil import FileLock, ensure_private_dir, replace_with_retry, rmtree_force, sha256_file
from .models import Confidence, Exposure, Match, Purpose
from .policy import require_aup

SCHEMA_VERSION = 1
GENESIS = "0" * 64
DEFAULT_ACTOR = "operator"
MAX_EVIDENCE_BYTES = 2 * 1024**3
CASE_ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
_ACTION_RE = re.compile(r"^[a-z0-9_.]{1,64}$")

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON (sorted keys, ASCII only) so other tools can recompute hashes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + b"\n" + canonical_json(entry)).hexdigest()


def new_case_id(now: datetime, token: Callable[[int], str] = secrets.token_hex) -> str:
    return f"{now.astimezone(timezone.utc):%Y%m%d-%H%M%S}-{token(3)}"


def validate_case_id(value: str) -> str:
    if not CASE_ID_RE.fullmatch(value):
        raise InvalidCaseIdError(value=value)
    return value


# --- records ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceRecord:
    id: str
    seq: int
    kind: str
    sha256: str
    size: int
    media_type: str | None
    source: str
    method: str
    exposure: str
    collected_at: str
    note: str | None
    meta: dict[str, Any]


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: str
    actor: str
    action: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True)
class CaseSummary:
    case_id: str
    title: str
    purpose: str
    created_at: str
    evidence_count: int


@dataclass(frozen=True)
class IndicatorRow:
    id: int
    type: str
    value: str
    attrs: dict[str, Any]
    observations: int
    evidence_ids: list[str]
    max_confidence: str


@dataclass(frozen=True)
class ObservationRow:
    indicator_id: int
    type: str
    value: str
    evidence_id: str
    start: int
    end: int
    confidence: str
    derived: bool


@dataclass(frozen=True)
class VerifyIssue:
    code: str
    detail: str
    severity: str = "error"  # error | warning


@dataclass
class VerifyReport:
    ok: bool
    issues: list[VerifyIssue] = field(default_factory=list)
    audit_head: dict[str, Any] | None = None
    entries_checked: int = 0
    evidence_checked: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "audit_head": self.audit_head, "entries_checked": self.entries_checked,
                "evidence_checked": self.evidence_checked,
                "issues": [{"code": i.code, "detail": i.detail, "severity": i.severity} for i in self.issues]}


_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE audit (
    seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
    payload TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE evidence (
    id TEXT PRIMARY KEY, seq INTEGER NOT NULL UNIQUE, kind TEXT NOT NULL, sha256 TEXT NOT NULL,
    size INTEGER NOT NULL, media_type TEXT, source TEXT NOT NULL, method TEXT NOT NULL,
    exposure TEXT NOT NULL, collected_at TEXT NOT NULL, note TEXT, meta TEXT NOT NULL
);
CREATE INDEX idx_evidence_sha ON evidence(sha256);
CREATE TABLE indicator (
    id INTEGER PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL, attrs TEXT NOT NULL DEFAULT '{}',
    UNIQUE (type, value)
);
CREATE TABLE observation (
    id INTEGER PRIMARY KEY,
    indicator_id INTEGER NOT NULL REFERENCES indicator(id),
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    start_off INTEGER NOT NULL, end_off INTEGER NOT NULL, raw TEXT NOT NULL, context TEXT NOT NULL,
    confidence TEXT NOT NULL, extractor TEXT NOT NULL, derived INTEGER NOT NULL DEFAULT 0,
    UNIQUE (indicator_id, evidence_id, start_off, end_off, extractor)
);
CREATE TABLE analysis (
    id INTEGER PRIMARY KEY, kind TEXT NOT NULL, evidence_id TEXT REFERENCES evidence(id),
    created_at TEXT NOT NULL, tool_version TEXT NOT NULL, result TEXT NOT NULL
);
"""


class Case:
    """An open case. Obtain one from :class:`Vault`; use as a context manager."""

    def __init__(self, directory: Path, *, clock: Clock = utc_now, actor: str = DEFAULT_ACTOR,
                 lock_timeout: float = 15.0) -> None:
        self.dir = Path(directory)
        self.case_id = self.dir.name
        self.blobs = self.dir / "blobs"
        self.actor = actor
        self._clock = clock
        self._lock_timeout = lock_timeout
        self._lock_depth = 0
        db = self.dir / "case.db"
        if not db.is_file():
            raise CaseNotFoundError(case_id=self.case_id, home=str(self.dir.parent.parent))
        try:
            self._conn = sqlite3.connect(db, isolation_level=None, timeout=lock_timeout)
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA secure_delete=ON")
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise VaultLockedError(seconds=lock_timeout) from exc
            raise VaultIntegrityError(detail=f"cannot open database: {exc}") from exc
        except sqlite3.DatabaseError as exc:
            raise VaultIntegrityError(detail=f"cannot open database: {exc}") from exc
        if version > SCHEMA_VERSION:
            self._conn.close()
            raise VaultTooNewError(version=version, supported=SCHEMA_VERSION)

    # -- lifecycle ----------------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Case":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals ----------------------------------------------------------------------------

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        if self._lock_depth:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        lock = FileLock(self.dir / ".lock", timeout=self._lock_timeout)
        lock.acquire()
        self._lock_depth = 1
        try:
            yield
        finally:
            self._lock_depth = 0
            lock.release()

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            raise VaultLockedError(seconds=self._lock_timeout) from exc
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def _now(self) -> str:
        return iso(self._clock())

    def _append_audit(self, conn: sqlite3.Connection, action: str, payload: dict[str, Any]) -> AuditEntry:
        if not _ACTION_RE.match(action):
            raise ValidationError(f"invalid audit action: {action!r}")
        row = conn.execute("SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
        ts = self._now()
        entry = {"seq": seq, "ts": ts, "actor": self.actor, "action": action, "payload": payload}
        digest = entry_hash(prev, entry)
        conn.execute(
            "INSERT INTO audit(seq, ts, actor, action, payload, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?)",
            (seq, ts, self.actor, action, canonical_json(payload).decode("ascii"), prev, digest),
        )
        return AuditEntry(seq, ts, self.actor, action, payload, prev, digest)

    def _blob_path(self, sha: str) -> Path:
        return self.blobs / sha[:2] / sha

    # -- metadata -----------------------------------------------------------------------------

    def meta(self) -> dict[str, str]:
        return dict(self._conn.execute("SELECT key, value FROM meta").fetchall())

    @property
    def title(self) -> str:
        return self.meta().get("title", "")

    @property
    def purpose(self) -> str:
        return self.meta().get("purpose", "")

    def log(self, action: str, payload: dict[str, Any] | None = None) -> AuditEntry:
        """Append a custom audit event (e.g. a policy override chosen by the operator)."""
        with self._locked(), self._tx() as conn:
            return self._append_audit(conn, action, payload or {})

    # -- evidence -----------------------------------------------------------------------------

    def add_evidence(self, data: bytes, **kw: Any) -> EvidenceRecord:
        return self._add_chunks([data], **kw)

    def add_evidence_file(self, path: Path, **kw: Any) -> EvidenceRecord:
        with open(path, "rb") as fh:
            return self._add_chunks(iter(lambda: fh.read(1 << 20), b""), **kw)

    def _add_chunks(
        self,
        chunks: Iterable[bytes],
        *,
        kind: str,
        source: str,
        method: str,
        exposure: Exposure = Exposure.NONE,
        media_type: str | None = None,
        note: str | None = None,
        meta: dict[str, Any] | None = None,
        max_bytes: int = MAX_EVIDENCE_BYTES,
    ) -> EvidenceRecord:
        with self._locked():
            tmp = self.blobs / f".tmp-{secrets.token_hex(8)}"
            h = hashlib.sha256()
            size = 0
            try:
                with open(tmp, "xb") as fh:
                    for chunk in chunks:
                        size += len(chunk)
                        if size > max_bytes:
                            raise InputTooLargeError(size=size, limit=max_bytes)
                        h.update(chunk)
                        fh.write(chunk)
                    fh.flush()
                    os.fsync(fh.fileno())
                digest = h.hexdigest()
                final = self._blob_path(digest)
                deduplicated = final.exists()
                if deduplicated:
                    os.unlink(tmp)
                else:
                    final.parent.mkdir(parents=True, exist_ok=True)
                    replace_with_retry(tmp, final)
                    with contextlib.suppress(OSError):
                        os.chmod(final, 0o400)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            collected = self._now()
            meta = meta or {}
            with self._tx() as conn:
                seq = conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM evidence").fetchone()[0]
                ev_id = f"E{seq:04d}"
                conn.execute(
                    "INSERT INTO evidence(id, seq, kind, sha256, size, media_type, source, method, exposure,"
                    " collected_at, note, meta) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ev_id, seq, kind, digest, size, media_type, source, method, str(exposure), collected, note,
                     canonical_json(meta).decode("ascii")),
                )
                self._append_audit(conn, "evidence.add", {
                    "id": ev_id, "kind": kind, "sha256": digest, "size": size, "source": source, "method": method,
                    "exposure": str(exposure), "deduplicated": deduplicated,
                })
            return EvidenceRecord(ev_id, seq, kind, digest, size, media_type, source, method, str(exposure),
                                  collected, note, meta)

    @staticmethod
    def _row_to_evidence(r: tuple[Any, ...]) -> EvidenceRecord:
        return EvidenceRecord(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], json.loads(r[11]))

    _EV_COLS = "id, seq, kind, sha256, size, media_type, source, method, exposure, collected_at, note, meta"

    def list_evidence(self) -> list[EvidenceRecord]:
        rows = self._conn.execute(f"SELECT {self._EV_COLS} FROM evidence ORDER BY seq").fetchall()
        return [self._row_to_evidence(r) for r in rows]

    def get_evidence(self, evidence_id: str) -> EvidenceRecord:
        r = self._conn.execute(f"SELECT {self._EV_COLS} FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        if r is None:
            raise ValidationError(key="error.validation.unknown_evidence", id=evidence_id)
        return self._row_to_evidence(r)

    def blob_path(self, sha256: str) -> Path:
        return self._blob_path(sha256)

    def read_blob(self, sha256: str, *, limit: int = MAX_EVIDENCE_BYTES) -> bytes:
        """Read an evidence file and verify its hash; raises ``VaultIntegrityError`` if it changed."""
        path = self._blob_path(sha256)
        try:
            if path.stat().st_size > limit:
                raise InputTooLargeError(size=path.stat().st_size, limit=limit)
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise VaultIntegrityError(detail=f"missing evidence file {sha256[:12]}") from exc
        if hashlib.sha256(data).hexdigest() != sha256:
            raise VaultIntegrityError(detail=f"evidence file {sha256[:12]} does not match its hash")
        return data

    # -- indicators ---------------------------------------------------------------------------

    def record_observations(self, evidence_id: str, rows: Sequence[tuple[Match, str]], extractor_version: str) -> int:
        """Store ``(match, context)`` pairs for an evidence item. Idempotent; returns rows inserted."""
        self.get_evidence(evidence_id)
        inserted = 0
        by_type: dict[str, int] = {}
        with self._locked(), self._tx() as conn:
            for match, context in rows:
                conn.execute("INSERT OR IGNORE INTO indicator(type, value, attrs) VALUES (?,?,?)",
                             (str(match.type), match.value, canonical_json(match.attrs).decode("ascii")))
                ind_id = conn.execute("SELECT id FROM indicator WHERE type=? AND value=?",
                                      (str(match.type), match.value)).fetchone()[0]
                cur = conn.execute(
                    "INSERT OR IGNORE INTO observation(indicator_id, evidence_id, start_off, end_off, raw, context,"
                    " confidence, extractor, derived) VALUES (?,?,?,?,?,?,?,?,?)",
                    (ind_id, evidence_id, match.start, match.end, match.raw[:500], context[:400],
                     str(match.confidence), match.extractor, int(match.derived)),
                )
                if cur.rowcount:
                    inserted += 1
                    by_type[str(match.type)] = by_type.get(str(match.type), 0) + 1
            self._append_audit(conn, "indicators.extract", {
                "evidence_id": evidence_id, "extractor_version": extractor_version, "inserted": inserted,
                "by_type": by_type,
            })
        return inserted

    def list_indicators(self) -> list[IndicatorRow]:
        out = []
        rank = {"high": 3, "medium": 2, "low": 1}
        q = ("SELECT i.id, i.type, i.value, i.attrs, o.evidence_id, o.confidence FROM indicator i"
             " JOIN observation o ON o.indicator_id = i.id ORDER BY i.type, i.value, o.evidence_id")
        grouped: dict[int, dict[str, Any]] = {}
        for iid, typ, val, attrs, ev, conf in self._conn.execute(q):
            g = grouped.setdefault(iid, {"type": typ, "value": val, "attrs": json.loads(attrs), "n": 0,
                                         "evs": [], "conf": "low"})
            g["n"] += 1
            if ev not in g["evs"]:
                g["evs"].append(ev)
            if rank[conf] > rank[g["conf"]]:
                g["conf"] = conf
        for iid, g in grouped.items():
            out.append(IndicatorRow(iid, g["type"], g["value"], g["attrs"], g["n"], g["evs"], g["conf"]))
        return sorted(out, key=lambda r: (r.type, r.value))

    def list_observations(self) -> list[ObservationRow]:
        q = ("SELECT i.id, i.type, i.value, o.evidence_id, o.start_off, o.end_off, o.confidence, o.derived"
             " FROM observation o JOIN indicator i ON i.id = o.indicator_id ORDER BY o.evidence_id, o.start_off")
        return [ObservationRow(r[0], r[1], r[2], r[3], r[4], r[5], r[6], bool(r[7])) for r in self._conn.execute(q)]

    # -- analyses -----------------------------------------------------------------------------

    def save_analysis(self, kind: str, evidence_id: str | None, result: dict[str, Any]) -> int:
        payload = canonical_json(result)
        with self._locked(), self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO analysis(kind, evidence_id, created_at, tool_version, result) VALUES (?,?,?,?,?)",
                (kind, evidence_id, self._now(), __version__, payload.decode("ascii")),
            )
            aid = int(cur.lastrowid or 0)
            self._append_audit(conn, "analysis.save", {
                "id": aid, "kind": kind, "evidence_id": evidence_id,
                "result_sha256": hashlib.sha256(payload).hexdigest(),
            })
        return aid

    def list_analyses(self, kind: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT id, kind, evidence_id, created_at, tool_version, result FROM analysis"
        args: tuple[Any, ...] = ()
        if kind:
            q, args = q + " WHERE kind = ?", (kind,)
        rows = self._conn.execute(q + " ORDER BY id", args).fetchall()
        return [{"id": r[0], "kind": r[1], "evidence_id": r[2], "created_at": r[3], "tool_version": r[4],
                 "result": json.loads(r[5])} for r in rows]

    # -- audit & integrity --------------------------------------------------------------------

    def audit_entries(self) -> list[AuditEntry]:
        rows = self._conn.execute(
            "SELECT seq, ts, actor, action, payload, prev_hash, entry_hash FROM audit ORDER BY seq").fetchall()
        return [AuditEntry(r[0], r[1], r[2], r[3], json.loads(r[4]), r[5], r[6]) for r in rows]

    def anchor(self) -> dict[str, Any] | None:
        """The current head of the audit chain; publish/timestamp it to fix the vault in time."""
        r = self._conn.execute("SELECT seq, entry_hash, ts FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return {"seq": r[0], "entry_hash": r[1], "ts": r[2]} if r else None

    def verify(self) -> VerifyReport:
        issues: list[VerifyIssue] = []
        add = lambda code, detail, sev="error": issues.append(VerifyIssue(code, detail, sev))  # noqa: E731
        conn = self._conn
        try:
            res = conn.execute("PRAGMA integrity_check").fetchall()
        except sqlite3.DatabaseError as exc:
            res = [(str(exc),)]
        if res != [("ok",)]:
            add("DB_INTEGRITY", "; ".join(str(r[0]) for r in res)[:300])

        prev, expect, entries, head = GENESIS, 1, 0, None
        audit_ev: dict[str, dict[str, Any]] = {}
        audit_an: dict[int, dict[str, Any]] = {}
        try:
            audit_rows = conn.execute(
                "SELECT seq, ts, actor, action, payload, prev_hash, entry_hash FROM audit ORDER BY seq").fetchall()
        except sqlite3.DatabaseError as exc:
            audit_rows = []
            add("DB_UNREADABLE", str(exc)[:300])
        for seq, ts, actor, action, payload_s, prev_hash, stored in audit_rows:
            entries += 1
            if seq != expect:
                add("AUDIT_SEQ_GAP", f"expected entry {expect}, found {seq}")
            if prev_hash != prev:
                add("AUDIT_CHAIN_BROKEN", f"entry {seq} does not link to the previous entry")
            try:
                payload = json.loads(payload_s)
            except json.JSONDecodeError:
                add("AUDIT_PAYLOAD_INVALID", f"entry {seq}")
                payload = {}
            recomputed = entry_hash(prev_hash, {"seq": seq, "ts": ts, "actor": actor, "action": action,
                                                "payload": payload})
            if recomputed != stored:
                add("AUDIT_HASH_MISMATCH", f"entry {seq} was modified")
            if action == "evidence.add" and isinstance(payload, dict):
                audit_ev[payload.get("id", "")] = payload
            elif action == "analysis.save" and isinstance(payload, dict):
                audit_an[int(payload.get("id", -1))] = payload
            prev, expect, head = stored, seq + 1, {"seq": seq, "entry_hash": stored}

        evidence = self.list_evidence() if not any(i.code == "DB_UNREADABLE" for i in issues) else []
        known: set[str] = set()
        for ev in evidence:
            a = audit_ev.pop(ev.id, None)
            if a is None:
                add("EVIDENCE_NOT_IN_AUDIT", f"{ev.id} has no audit entry")
            elif (a.get("sha256"), a.get("size"), a.get("source"), a.get("kind")) != (ev.sha256, ev.size, ev.source, ev.kind):
                add("EVIDENCE_AUDIT_MISMATCH", f"{ev.id} differs from its audit entry")
            known.add(ev.sha256)
            path = self._blob_path(ev.sha256)
            if not path.is_file():
                add("BLOB_MISSING", f"{ev.id}: {ev.sha256[:12]}")
                continue
            digest, size = sha256_file(path)
            if digest != ev.sha256 or size != ev.size:
                add("BLOB_CORRUPT", f"{ev.id}: stored bytes no longer match {ev.sha256[:12]}")
        for ev_id in audit_ev:
            add("EVIDENCE_MISSING_FROM_DB", f"{ev_id} is in the audit log but not in the database")

        for a in self.list_analyses():
            entry = audit_an.get(a["id"])
            result_hash = hashlib.sha256(canonical_json(a["result"])).hexdigest()
            if entry is None:
                add("ANALYSIS_NOT_IN_AUDIT", f"analysis {a['id']}")
            elif entry.get("result_sha256") != result_hash:
                add("ANALYSIS_MODIFIED", f"analysis {a['id']} ({a['kind']}) was changed after it was recorded")

        if self.blobs.is_dir():
            for sub in self.blobs.iterdir():
                children = sub.iterdir() if sub.is_dir() else [sub]
                for f in children:
                    if f.name.startswith(".tmp-"):
                        add("BLOB_TMP_LEFTOVER", f.name, "warning")
                    elif f.name not in known:
                        add("BLOB_ORPHAN", f.name[:12], "warning")
        ok = not any(i.severity == "error" for i in issues)
        return VerifyReport(ok, issues, head, entries, len(evidence))


class Vault:
    """All cases under one data directory."""

    def __init__(self, home: Path, *, clock: Clock = utc_now, actor: str = DEFAULT_ACTOR) -> None:
        self.home = Path(home)
        self.cases_dir = self.home / "cases"
        self.clock = clock
        self.actor = actor

    def create_case(self, title: str, purpose: Purpose, *, accept_aup: bool, actor: str | None = None) -> Case:
        require_aup(accept_aup)
        title = re.sub(r"[\x00-\x1f\x7f]", " ", title).strip()
        if not title or len(title) > 200:
            raise ValidationError(key="error.validation.title")
        ensure_private_dir(self.cases_dir)
        now = self.clock()
        for _ in range(5):
            case_id = new_case_id(now)
            path = self.cases_dir / case_id
            try:
                os.mkdir(path, 0o700)
                break
            except FileExistsError:
                continue
        else:  # pragma: no cover - 5 collisions of 24 random bits
            raise VaultError(detail="could not allocate a case id")
        try:
            ensure_private_dir(path / "blobs")
            conn = sqlite3.connect(path / "case.db", isolation_level=None)
            try:
                conn.executescript(_SCHEMA)
                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                created = iso(now)
                for k, v in (("case_id", case_id), ("title", title), ("purpose", str(purpose)),
                             ("created_at", created), ("tool_version", __version__), ("aup_version", AUP_VERSION)):
                    conn.execute("INSERT INTO meta(key, value) VALUES (?,?)", (k, v))
            finally:
                conn.close()
            case = Case(path, clock=self.clock, actor=actor or self.actor)
            with case._locked(), case._tx() as c:
                case._append_audit(c, "case.create", {"case_id": case_id, "title": title, "purpose": str(purpose),
                                                      "tool_version": __version__})
                case._append_audit(c, "policy.aup_accepted", {"aup_version": AUP_VERSION})
            return case
        except BaseException:
            rmtree_force(path)
            raise

    def open_case(self, case_id: str, *, actor: str | None = None) -> Case:
        validate_case_id(case_id)
        return Case(self.cases_dir / case_id, clock=self.clock, actor=actor or self.actor)

    def list_cases(self) -> list[CaseSummary]:
        if not self.cases_dir.is_dir():
            return []
        out = []
        for d in sorted(self.cases_dir.iterdir()):
            if not (d.is_dir() and CASE_ID_RE.fullmatch(d.name) and (d / "case.db").is_file()):
                continue
            try:
                conn = sqlite3.connect(f"{(d / 'case.db').as_uri()}?mode=ro", uri=True)
                try:
                    meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
                    count = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
                finally:
                    conn.close()
            except sqlite3.DatabaseError:
                continue
            out.append(CaseSummary(d.name, meta.get("title", ""), meta.get("purpose", ""),
                                   meta.get("created_at", ""), count))
        return out

    def delete_case(self, case_id: str) -> None:
        """Remove a case directory. Note: this is not a secure wipe on SSDs or journaling filesystems."""
        validate_case_id(case_id)
        path = self.cases_dir / case_id
        if not path.is_dir():
            raise CaseNotFoundError(case_id=case_id, home=str(self.home))
        rmtree_force(path)
