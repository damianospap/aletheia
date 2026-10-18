"""Capture a web page as evidence (this contacts the target's server: ``Exposure.ACTIVE``)."""

from __future__ import annotations

import json
from dataclasses import dataclass

from . import __version__
from .errors import TlsError, ValidationError
from .http import HttpClient, HttpResult
from .indexing import index_evidence, is_texty
from .indicators.urls import parse_url
from .models import Exposure
from .policy import require_active_confirmation
from .vault import Case, EvidenceRecord, canonical_json


@dataclass
class CaptureOutcome:
    body: EvidenceRecord
    meta: EvidenceRecord
    status: int
    final_url: str
    tls_verified: bool
    indicators: int


def _meta_document(result: HttpResult, *, ignored_robots: bool, tls_error: str | None) -> dict:
    return {
        "schema": "aletheia-http-capture/1",
        "tool_version": __version__,
        "requested_url": result.requested_url,
        "final_url": result.final_url,
        "status": result.status,
        "reason": result.reason,
        "headers": [[k, v] for k, v in result.headers],
        "redirect_chain": [{"url": h.url, "status": h.status, "location": h.location, "remote_ip": h.remote_ip}
                           for h in result.chain],
        "remote_ip": result.remote_ip,
        "tls": result.tls,
        "tls_verified": result.tls_verified,
        "tls_error": tls_error,
        "elapsed_ms": result.elapsed_ms,
        "attempts": result.attempts,
        "decoded_gzip": result.decoded_gzip,
        "user_agent": result.user_agent,
        "started_at": result.started_at,
        "robots": "ignored_by_operator" if ignored_robots else "respected",
        "body_sha256": result.body_sha256,
        "body_size": len(result.body),
    }


def capture_url(
    case: Case,
    url: str,
    client: HttpClient,
    *,
    confirm_active: bool,
    ignore_robots: bool = False,
    allow_invalid_tls: bool = False,
    user_agent: str | None = None,
) -> CaptureOutcome:
    info = parse_url(url)
    if info.has_userinfo:
        raise ValidationError(key="error.validation.credentials")
    if info.scheme not in ("http", "https"):
        raise ValidationError(key="error.validation.scheme", url=url)
    require_active_confirmation(info.canonical, confirm_active)
    case.log("capture.attempt", {"url": url, "ignore_robots": ignore_robots, "allow_invalid_tls": allow_invalid_tls,
                                 "user_agent": user_agent or client.policy.user_agent})
    tls_error: str | None = None
    try:
        result = client.get(url, user_agent=user_agent, check_robots=not ignore_robots)
    except TlsError as exc:
        if not allow_invalid_tls:
            raise
        tls_error = exc.detail
        result = client.get(url, user_agent=user_agent, check_robots=not ignore_robots, verify_tls=False)
        result.tls_verified = False
    body = case.add_evidence(
        result.body, kind="http_body", source=result.final_url, method="http_get", exposure=Exposure.ACTIVE,
        media_type=result.content_type,
        meta={"status": result.status, "requested_url": url, "tls_verified": result.tls_verified},
    )
    meta_doc = _meta_document(result, ignored_robots=ignore_robots, tls_error=tls_error)
    meta = case.add_evidence(
        json.dumps(meta_doc, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8"),
        kind="http_capture_meta", source=result.final_url, method="http_get", exposure=Exposure.ACTIVE,
        media_type="application/json", meta={"describes": body.id},
    )
    indexed = index_evidence(case, body.id) if is_texty(body.media_type, body.kind) else 0
    return CaptureOutcome(body, meta, result.status, result.final_url, result.tls_verified, indexed)
