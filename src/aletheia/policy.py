"""Policy gates ("legal by design").

Aletheia is a local tool with no vetting step (unlike a commercial vendor), so responsibility is
enforced in the workflow instead:

* a case cannot be created without recording acceptance of the Acceptable Use Policy and a purpose;
* anything that contacts target-controlled infrastructure needs an explicit, per-action confirmation;
* the *publication* report profile masks personal data by default, and every override is audited.
"""

from __future__ import annotations

from enum import StrEnum

from .errors import ActiveConfirmationRequired, AupNotAcceptedError
from .models import PERSONAL_TYPES, IndicatorType

#: i18n keys of the short AUP summary shown when a case is created.
AUP_KEYS = tuple(f"aup.item{i}" for i in range(1, 7))


class ReportProfile(StrEnum):
    HANDOVER = "handover"  # complete, for law enforcement / lawyers
    PUBLICATION = "publication"  # personal data masked, no raw evidence files


def require_aup(accepted: bool) -> None:
    if not accepted:
        raise AupNotAcceptedError()


def require_active_confirmation(url: str, confirmed: bool) -> None:
    if not confirmed:
        raise ActiveConfirmationRequired(url=url)


def _mask_email(v: str) -> str:
    local, _, domain = v.partition("@")
    return f"{local[:1]}***@{domain}"


def _mask_phone(v: str) -> str:
    digits = v.lstrip("+")
    return f"+{digits[:2]}{'•' * max(0, len(digits) - 4)}{digits[-2:]}" if len(digits) > 4 else "•" * len(v)


def _mask_iban(v: str) -> str:
    return f"{v[:4]}{'•' * max(0, len(v) - 6)}{v[-2:]}"


def _mask_handle(v: str) -> str:
    platform, _, handle = v.partition(":")
    return f"{platform}:{handle[:2]}{'•' * max(0, len(handle) - 2)}"


_MASKERS = {
    IndicatorType.EMAIL: _mask_email,
    IndicatorType.PHONE: _mask_phone,
    IndicatorType.IBAN: _mask_iban,
    IndicatorType.HANDLE: _mask_handle,
}


def mask_value(itype: IndicatorType | str, value: str) -> str:
    """Mask a personal-data indicator for publication (other types are returned unchanged)."""
    itype = IndicatorType(itype)
    if itype in PERSONAL_TYPES:
        return _MASKERS[itype](value)
    return value
