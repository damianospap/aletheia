"""Cryptocurrency address validation (checksum-verified, no network).

Supported: Bitcoin legacy (Base58Check), Bitcoin SegWit/Taproot (Bech32/Bech32m, BIP-173/350),
Ethereum-style 0x addresses (EIP-55 checksum when mixed case) and TRON (Base58Check, 0x41).
USDT-TRC20 on TRON and USDT/USDC on Ethereum are common payment rails in scams.

Keccak-256 is implemented here because ``hashlib.sha3_256`` is NIST SHA-3 (different padding).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from ..models import Confidence

# --- Keccak-256 (original Keccak padding, as used by Ethereum) -------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
    0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_M64 = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _M64 if n else x


def _keccak_f(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136  # (1600 - 2*256) / 8
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * ((-len(padded)) % rate)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        block = padded[off : off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8 * i : 8 * i + 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)
    out = b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out[:32]


# --- Base58Check -----------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def b58decode(s: str) -> bytes | None:
    n = 0
    for ch in s:
        if ch not in _B58_INDEX:
            return None
        n = n * 58 + _B58_INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def b58check_decode(s: str) -> bytes | None:
    raw = b58decode(s)
    if raw is None or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    return payload if _sha256d(payload)[:4] == checksum else None


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + _sha256d(payload)[:4])


# --- Bech32 / Bech32m ------------------------------------------------------------------------

_BECH_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _bech_polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= _BECH_GEN[i] if (top >> i) & 1 else 0
    return chk


def _bech_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_decode(s: str) -> tuple[str, list[int], str] | None:
    """Decode a Bech32/Bech32m string -> (hrp, data5bit, variant) or None."""
    if s != s.lower() and s != s.upper():
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or len(s) > 90:
        return None
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        return None
    hrp, rest = s[:pos], s[pos + 1 :]
    if any(c not in _BECH_CHARSET for c in rest):
        return None
    data = [_BECH_CHARSET.find(c) for c in rest]
    polymod = _bech_polymod(_bech_hrp_expand(hrp) + data)
    if polymod == 1:
        return hrp, data[:-6], "bech32"
    if polymod == 0x2BC830A3:
        return hrp, data[:-6], "bech32m"
    return None


def bech32_encode(hrp: str, data: list[int], variant: str = "bech32") -> str:
    const = 0x2BC830A3 if variant == "bech32m" else 1
    values = _bech_hrp_expand(hrp) + data
    mod = _bech_polymod(values + [0] * 6) ^ const
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH_CHARSET[d] for d in data + checksum)


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool) -> list[int] | None:
    acc = bits = 0
    out: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out


# --- public API ------------------------------------------------------------------------------


@dataclass(frozen=True)
class WalletInfo:
    chain: str  # btc | eth | trx
    address: str  # canonical form
    kind: str  # p2pkh | p2sh | segwit_v0 | taproot | witness_v1plus | evm | tron
    confidence: Confidence
    note: str | None = None


def _eip55(addr_lower_hex: str) -> str:
    digest = keccak256(addr_lower_hex.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(addr_lower_hex))


def validate_wallet(candidate: str) -> WalletInfo | None:
    """Validate ``candidate`` as BTC / ETH(EVM) / TRON address; ``None`` if invalid."""
    s = candidate.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", s):
        body = s[2:]
        if body == body.lower() or body == body.upper():
            return WalletInfo("eth", "0x" + body.lower(), "evm", Confidence.MEDIUM, "no_checksum_case")
        if _eip55(body.lower()) == "0x" + body:
            return WalletInfo("eth", "0x" + body.lower(), "evm", Confidence.HIGH, "eip55_ok")
        return None  # mixed case but wrong checksum: likely mistyped/forged
    decoded = bech32_decode(s) if s[:3].lower() == "bc1" else None
    if decoded:
        hrp, data, variant = decoded
        if hrp != "bc" or not data:
            return None
        witver, program = data[0], _convertbits(data[1:], 5, 8, False)
        if witver > 16 or program is None or not 2 <= len(program) <= 40:
            return None
        if witver == 0 and (variant != "bech32" or len(program) not in (20, 32)):
            return None
        if witver != 0 and variant != "bech32m":
            return None
        kind = "segwit_v0" if witver == 0 else ("taproot" if witver == 1 and len(program) == 32 else "witness_v1plus")
        return WalletInfo("btc", s.lower(), kind, Confidence.HIGH)
    if s[:1] in "13" and 26 <= len(s) <= 35:
        payload = b58check_decode(s)
        if payload and len(payload) == 21 and payload[0] in (0x00, 0x05):
            return WalletInfo("btc", s, "p2pkh" if payload[0] == 0 else "p2sh", Confidence.HIGH)
    if s[:1] == "T" and len(s) == 34:
        payload = b58check_decode(s)
        if payload and len(payload) == 21 and payload[0] == 0x41:
            return WalletInfo("trx", s, "tron", Confidence.HIGH)
    return None


_CANDIDATES = re.compile(
    r"(?<![A-Za-z0-9])(?:0x[0-9a-fA-F]{40}|(?:bc1|BC1)[A-Za-z0-9]{11,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34}|T[1-9A-HJ-NP-Za-km-z]{33})(?![A-Za-z0-9])"
)


def find_wallets(text: str) -> list[tuple[int, int, WalletInfo]]:
    out = []
    for m in _CANDIDATES.finditer(text):
        info = validate_wallet(m.group(0))
        if info:
            out.append((m.start(), m.end(), info))
    return out
