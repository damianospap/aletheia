"""Phone numbers: E.164 normalisation, calling-code region, Greek number classification.

This is deliberately *not* a full numbering-plan library: only Greece is validated strictly.
Other regions are checked for a known calling code and a plausible total length (E.164: max 15).
The ``region`` attribute is the calling-code region, not the carrier or the physical location.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Confidence

# Calling code -> region (shared codes such as +1 are reported as NANP).
CALLING_CODES: dict[str, str] = {
    "1": "NANP", "7": "RU/KZ", "20": "EG", "27": "ZA", "30": "GR", "31": "NL", "32": "BE", "33": "FR",
    "34": "ES", "36": "HU", "39": "IT", "40": "RO", "41": "CH", "43": "AT", "44": "GB", "45": "DK",
    "46": "SE", "47": "NO", "48": "PL", "49": "DE", "51": "PE", "52": "MX", "53": "CU", "54": "AR",
    "55": "BR", "56": "CL", "57": "CO", "58": "VE", "60": "MY", "61": "AU", "62": "ID", "63": "PH",
    "64": "NZ", "65": "SG", "66": "TH", "81": "JP", "82": "KR", "84": "VN", "86": "CN", "90": "TR",
    "91": "IN", "92": "PK", "93": "AF", "94": "LK", "95": "MM", "98": "IR", "212": "MA", "213": "DZ",
    "216": "TN", "218": "LY", "220": "GM", "221": "SN", "233": "GH", "234": "NG", "251": "ET", "254": "KE",
    "255": "TZ", "256": "UG", "260": "ZM", "263": "ZW", "351": "PT", "352": "LU", "353": "IE", "354": "IS",
    "355": "AL", "356": "MT", "357": "CY", "358": "FI", "359": "BG", "370": "LT", "371": "LV", "372": "EE",
    "373": "MD", "374": "AM", "375": "BY", "376": "AD", "377": "MC", "378": "SM", "380": "UA", "381": "RS",
    "382": "ME", "383": "XK", "385": "HR", "386": "SI", "387": "BA", "389": "MK", "420": "CZ", "421": "SK",
    "423": "LI", "852": "HK", "853": "MO", "855": "KH", "856": "LA", "880": "BD", "886": "TW", "961": "LB",
    "962": "JO", "963": "SY", "964": "IQ", "965": "KW", "966": "SA", "967": "YE", "968": "OM", "971": "AE",
    "972": "IL", "973": "BH", "974": "QA", "975": "BT", "976": "MN", "977": "NP", "992": "TJ", "993": "TM",
    "994": "AZ", "995": "GE", "996": "KG", "998": "UZ",
}

_GR_TYPES = (("69", "mobile"), ("800", "toll_free"), ("801", "shared_cost"), ("90", "premium_rate"),
             ("70", "personal"), ("2", "landline"))


@dataclass(frozen=True)
class PhoneInfo:
    e164: str
    country_code: str | None
    region: str | None
    line_type: str | None
    confidence: Confidence


def _split_country_code(digits: str) -> tuple[str, str] | None:
    for length in (1, 2, 3):  # ITU calling codes are prefix-free
        code = digits[:length]
        if code in CALLING_CODES:
            return code, digits[length:]
    return None


def normalize_phone(raw: str, default_region: str | None = "GR") -> PhoneInfo | None:
    """Normalise ``raw`` to E.164, or return ``None`` if it is not a plausible phone number."""
    s = raw.strip()
    plus = bool(re.match(r"^[^\d+]*\+", s))  # a "+" before the first digit, e.g. "(+30) 694..."
    digits = re.sub(r"\D", "", s)
    if not digits:
        return None
    if not plus and digits.startswith("00"):
        plus, digits = True, digits[2:]
    if not plus:
        if default_region == "GR" and len(digits) == 10 and (digits.startswith("69") or digits.startswith("2")):
            digits = "30" + digits
            national_format = True
        else:
            return None
    else:
        national_format = False
    if not 7 <= len(digits) <= 15:
        return None
    split = _split_country_code(digits)
    if split is None:
        return PhoneInfo("+" + digits, None, None, None, Confidence.LOW)
    code, national = split
    region = CALLING_CODES[code]
    if code == "30":
        if len(national) != 10:
            return None
        line_type = next((t for prefix, t in _GR_TYPES if national.startswith(prefix)), "unknown")
        if national_format:
            conf = Confidence.MEDIUM if line_type == "mobile" else Confidence.LOW
        else:
            conf = Confidence.HIGH
        return PhoneInfo("+" + digits, code, region, line_type, conf)
    if len(national) < 4:
        return None
    return PhoneInfo("+" + digits, code, region, None, Confidence.MEDIUM)


_INTL_RE = re.compile(r"(?<![\w@./+-])(?:\+|00)[ \t]?\d(?:[ \t().-]?\d){6,14}(?![\w@-]|\.\d)")
_GR_NATIONAL_RE = re.compile(r"(?<![\w@./+-])(?:69(?:[ .-]?\d){8}|2(?:[ .-]?\d){9})(?![\d@]|[ .-]\d)")


def find_phones(text: str) -> list[tuple[int, int, str]]:
    """Candidate phone strings as ``(start, end, raw)`` (validation happens in ``normalize_phone``)."""
    found = [(m.start(), m.end(), m.group(0)) for m in _INTL_RE.finditer(text)]
    found += [(m.start(), m.end(), m.group(0)) for m in _GR_NATIONAL_RE.finditer(text)]
    return found
