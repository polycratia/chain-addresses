"""Base58Check encoding used by extended key serialisation."""

from __future__ import annotations

import pytest

from chain_addresses.base58 import b58check_decode, b58check_encode
from chain_addresses.errors import Base58Error


@pytest.mark.parametrize(
    "payload",
    [
        b"\x00",
        b"\x00" * 21,
        b"\x00\x00\x01",
        bytes(range(32)),
        b"\xff" * 78,
    ],
)
def test_round_trip(payload: bytes) -> None:
    assert b58check_decode(b58check_encode(payload)) == payload


def test_leading_zero_bytes_become_leading_ones() -> None:
    text = b58check_encode(b"\x00\x00\x01")
    assert text.startswith("11")
    assert not text.startswith("111")


def test_empty_string_is_rejected() -> None:
    with pytest.raises(Base58Error, match="empty"):
        b58check_decode("")


@pytest.mark.parametrize("character", ["0", "O", "I", "l", "+", " "])
def test_alphabet_is_enforced(character: str) -> None:
    text = b58check_encode(b"\x01\x02\x03")
    with pytest.raises(Base58Error, match="invalid Base58 character"):
        b58check_decode(text[:-1] + character)


def test_string_too_short_for_a_checksum() -> None:
    with pytest.raises(Base58Error, match="too short"):
        b58check_decode("2222")


def test_checksum_mismatch_is_caught() -> None:
    text = b58check_encode(b"\x01\x02\x03\x04")
    tampered = text[:-1] + ("2" if text[-1] != "2" else "3")
    with pytest.raises(Base58Error, match="checksum"):
        b58check_decode(tampered)
