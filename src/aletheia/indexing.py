"""Glue between the vault and the extractors."""

from __future__ import annotations

from .indicators import EXTRACTOR_VERSION, context_for, extract_indicators
from .textnorm import decode_text
from .vault import Case

_TEXT_KINDS = ("text", "ig_thread", "http_body", "file")
_TEXTY_MEDIA = ("text/", "application/json", "application/xml", "application/xhtml", "application/javascript")


def is_texty(media_type: str | None, kind: str) -> bool:
    """Whether an evidence item should be run through text extractors."""
    if media_type:
        return media_type.lower().startswith(_TEXTY_MEDIA)
    return kind in _TEXT_KINDS


def index_evidence(case: Case, evidence_id: str, *, default_region: str | None = "GR") -> int:
    """Extract indicators from one evidence item and record them. Returns newly stored observations."""
    ev = case.get_evidence(evidence_id)
    if not is_texty(ev.media_type, ev.kind):
        return 0
    text, _enc, _lossy = decode_text(case.read_blob(ev.sha256))
    matches = extract_indicators(text, default_region=default_region)
    rows = [(m, context_for(text, m)) for m in matches]
    return case.record_observations(evidence_id, rows, EXTRACTOR_VERSION)
