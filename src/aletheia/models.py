"""Small shared value types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1}[self.value]


class Exposure(StrEnum):
    """What a collection step reveals, and to whom."""

    NONE = "none"  # offline: nothing leaves the machine
    PASSIVE = "passive_third_party"  # a public service learns what we asked about
    ACTIVE = "active_target"  # target-controlled infrastructure sees our IP address


class Purpose(StrEnum):
    JOURNALISM = "journalism"
    VICTIM_REPORT = "victim-report"


class IndicatorType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    EMAIL = "email"
    PHONE = "phone"
    IBAN = "iban"
    WALLET = "wallet"
    HANDLE = "handle"
    IP = "ip"


#: Indicator types that identify (or may identify) natural persons; masked in publication reports.
PERSONAL_TYPES = frozenset({IndicatorType.EMAIL, IndicatorType.PHONE, IndicatorType.IBAN, IndicatorType.HANDLE})


@dataclass(frozen=True, slots=True)
class Match:
    """One extracted indicator occurrence inside a text."""

    type: IndicatorType
    value: str  # canonical form
    raw: str  # exactly what appeared in the text
    start: int
    end: int
    confidence: Confidence
    extractor: str
    attrs: dict[str, Any] = field(default_factory=dict)
    derived: bool = False  # True if inferred from another match (e.g. domain from a URL)
