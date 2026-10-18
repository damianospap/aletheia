"""IBAN detection and validation (ISO 13616, mod-97).

Bank/BIC lookup is intentionally not included: it requires an authoritative registry and a
wrong guess in an evidence report is worse than none.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Confidence

# Country -> total IBAN length (ISO 13616 registry).
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
    "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
    "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
    "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19,
    "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29,
    "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28,
    "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}


@dataclass(frozen=True)
class IbanInfo:
    iban: str
    country: str
    check_digits: str
    bban: str
    bank_code: str | None  # for Greece: 3-digit bank + 4-digit branch code
    confidence: Confidence


def mod97(iban: str) -> int:
    rearranged = iban[4:] + iban[:4]
    number = "".join(str(int(c, 36)) for c in rearranged)
    return int(number) % 97


def validate_iban(candidate: str) -> IbanInfo | None:
    """Return details if ``candidate`` is a valid IBAN (spaces allowed), else ``None``."""
    iban = re.sub(r"[\s\u00a0-]", "", candidate).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", iban):
        return None
    country = iban[:2]
    expected = IBAN_LENGTHS.get(country)
    if expected is not None and len(iban) != expected:
        return None
    if mod97(iban) != 1:
        return None
    bank_code = iban[4:11] if country == "GR" else None
    return IbanInfo(iban, country, iban[2:4], iban[4:], bank_code, Confidence.HIGH if expected else Confidence.MEDIUM)


_CAND_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}(?:[ \u00a0-]?[A-Za-z0-9]){11,40}(?![A-Za-z0-9])")


def find_ibans(text: str) -> list[tuple[int, int, IbanInfo]]:
    """Find valid IBANs in text, trimming trailing words that the loose pattern swallowed."""
    found: list[tuple[int, int, IbanInfo]] = []
    for m in _CAND_RE.finditer(text):
        raw = m.group(0)
        # positions (in raw) of alphanumeric characters, to map "first N chars" back to an end offset
        alnum_pos = [i for i, c in enumerate(raw) if c.isalnum()]
        country = raw[:2].upper()
        lengths = [IBAN_LENGTHS[country]] if country in IBAN_LENGTHS else range(15, min(34, len(alnum_pos)) + 1)
        for length in lengths:
            if length > len(alnum_pos):
                continue
            end_rel = alnum_pos[length - 1] + 1
            info = validate_iban(raw[:end_rel])
            if info:
                found.append((m.start(), m.start() + end_rel, info))
                break
    return found
