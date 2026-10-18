"""Offline decoding of Instagram shortcodes and media IDs.

Instagram media IDs follow the layout described by Instagram's engineers: 41 bits of
milliseconds since a custom epoch (2011-08-24T21:07:01.721Z), 13 bits of shard and 10 bits of
sequence. The public ``/p/<shortcode>/`` is the media ID written in a base-64 alphabet.
The creation time derived this way is a *heuristic* (community-documented, not guaranteed by
Instagram) and must be reported with that caveat; it needs no network access.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .errors import ValidationError

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}
INSTAGRAM_EPOCH_MS = 1314220021721
_MAX_ID = (1 << 64) - 1
# IDs created before the layout was introduced are small sequential numbers; decoded naively they land
# within milliseconds of the custom epoch. Treat the first day after the epoch as "layout not applicable".
_SCHEME_START = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=INSTAGRAM_EPOCH_MS) + timedelta(days=1)


@dataclass(frozen=True)
class IgMediaId:
    shortcode: str
    media_id: int
    created_at: datetime
    shard: int
    sequence: int
    plausible: bool  # after the first day of the ID layout and not in the future (else: do not rely on the date)


def shortcode_to_media_id(shortcode: str) -> int:
    if not shortcode or len(shortcode) > 11:
        raise ValidationError(key="error.validation.shortcode_length", length=len(shortcode))
    value = 0
    for ch in shortcode:
        if ch not in _INDEX:
            raise ValidationError(key="error.validation.shortcode_char", char=ch)
        value = value * 64 + _INDEX[ch]
    if value > _MAX_ID:
        raise ValidationError(key="error.validation.shortcode_range")
    return value


def media_id_to_shortcode(media_id: int) -> str:
    if not 0 <= media_id <= _MAX_ID:
        raise ValidationError(key="error.validation.shortcode_range")
    chars = []
    while media_id:
        media_id, rem = divmod(media_id, 64)
        chars.append(ALPHABET[rem])
    return "".join(reversed(chars)) or "A"


def decode(shortcode: str, *, now: datetime | None = None) -> IgMediaId:
    media_id = shortcode_to_media_id(shortcode)
    ms = (media_id >> 23) + INSTAGRAM_EPOCH_MS
    created = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=ms)
    now = now or datetime.now(timezone.utc)
    return IgMediaId(
        shortcode=shortcode,
        media_id=media_id,
        created_at=created,
        shard=(media_id >> 10) & 0x1FFF,
        sequence=media_id & 0x3FF,
        plausible=_SCHEME_START <= created <= now + timedelta(days=1),
    )


def make_media_id(created: datetime, shard: int = 0, sequence: int = 0) -> int:
    """Inverse of the timestamp part (used by tests and for illustrating the layout)."""
    ms = int(created.astimezone(timezone.utc).timestamp() * 1000) - INSTAGRAM_EPOCH_MS
    return (ms << 23) | ((shard & 0x1FFF) << 10) | (sequence & 0x3FF)
