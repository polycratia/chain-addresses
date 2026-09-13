"""Base58Check encoding, as used by BIP32 extended key serialisation."""

from __future__ import annotations

from hashlib import sha256

from .errors import Base58Error

__all__ = ["ALPHABET", "b58check_decode", "b58check_encode"]

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {character: value for value, character in enumerate(ALPHABET)}


def _checksum(payload: bytes) -> bytes:
    return sha256(sha256(payload).digest()).digest()[:4]


def b58check_encode(payload: bytes) -> str:
    """Encode *payload* with a trailing four-byte double-SHA256 checksum."""
    data = payload + _checksum(payload)
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    digits: list[str] = []
    while number:
        number, remainder = divmod(number, 58)
        digits.append(ALPHABET[remainder])
    digits.append("1" * leading_zeros)
    return "".join(reversed(digits))


def b58check_decode(text: str) -> bytes:
    """Decode *text* and return the payload without its checksum."""
    if not text:
        raise Base58Error("empty Base58Check string")
    number = 0
    for character in text:
        try:
            number = number * 58 + _INDEX[character]
        except KeyError:
            raise Base58Error(f"invalid Base58 character {character!r}") from None
    leading_zeros = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    data = b"\x00" * leading_zeros + body
    if len(data) < 5:
        raise Base58Error("Base58Check string is too short to carry a checksum")
    payload, checksum = data[:-4], data[-4:]
    if _checksum(payload) != checksum:
        raise Base58Error("Base58Check checksum mismatch")
    return payload
