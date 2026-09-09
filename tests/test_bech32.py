"""Bech32 and bech32m, including the constant that separates them."""

from __future__ import annotations

import pytest

from chain_addresses.bech32 import decode, encode
from chain_addresses.errors import Bech32Error

KEY_HASH = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
PROGRAM32 = bytes(range(32))


def test_bip173_p2wpkh_vector() -> None:
    assert encode("bc", 0, KEY_HASH) == P2WPKH
    assert decode("bc", P2WPKH) == (0, KEY_HASH)


def test_an_uppercase_address_decodes_the_same() -> None:
    assert decode("bc", P2WPKH.upper()) == (0, KEY_HASH)


@pytest.mark.parametrize("version", range(17))
def test_round_trip(version: int) -> None:
    program = KEY_HASH if version == 0 else PROGRAM32
    assert decode("tb", encode("tb", version, program)) == (version, program)


def test_a_bech32m_string_does_not_pass_as_witness_version_zero() -> None:
    address = encode("bc", 1, PROGRAM32)
    hrp, data = address.split("1", 1)
    with pytest.raises(Bech32Error, match="checksum"):
        decode("bc", f"{hrp}1q{data[1:]}")


def test_a_tampered_checksum_is_caught() -> None:
    tampered = P2WPKH[:-1] + ("q" if P2WPKH[-1] != "q" else "p")
    with pytest.raises(Bech32Error, match="checksum"):
        decode("bc", tampered)


@pytest.mark.parametrize(
    ("version", "program"),
    [(0, KEY_HASH + b"\x00"), (17, PROGRAM32), (-1, PROGRAM32), (1, b"\x00"), (1, b"\x00" * 41)],
)
def test_encode_rejects_unusable_programs(version: int, program: bytes) -> None:
    with pytest.raises(Bech32Error):
        encode("bc", version, program)


@pytest.mark.parametrize(
    "address",
    [
        P2WPKH[:5].upper() + P2WPKH[5:],
        P2WPKH.replace("q", "b", 1),
        "qqqqqq",
        "bc1qqqqqq",
    ],
)
def test_decode_rejects_malformed_strings(address: str) -> None:
    with pytest.raises(Bech32Error):
        decode("bc", address)


def test_decode_rejects_a_foreign_prefix() -> None:
    with pytest.raises(Bech32Error, match="expected prefix"):
        decode("tb", P2WPKH)
