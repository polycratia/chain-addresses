"""Bech32 and bech32m, the checksummed encodings behind segwit outputs.

The two differ only in the constant the checksum is expected to reach: witness
version 0 uses bech32 (BIP173) and every later version uses bech32m (BIP350),
which repairs an insertion weakness in the original checksum.
"""

from __future__ import annotations

from collections.abc import Iterable

from .errors import Bech32Error

__all__ = ["CHARSET", "decode", "encode"]

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_BECH32_CONSTANT = 1
_BECH32M_CONSTANT = 0x2BC830A3
_MAX_LENGTH = 90
_CHECKSUM_LENGTH = 6


def _checksum_constant(witness_version: int) -> int:
    return _BECH32_CONSTANT if witness_version == 0 else _BECH32M_CONSTANT


def _polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for bit, generator in enumerate(_GENERATOR):
            if (top >> bit) & 1:
                checksum ^= generator
    return checksum


def _expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(
    values: Iterable[int], from_bits: int, to_bits: int, *, pad: bool
) -> list[int]:
    accumulator = 0
    bits = 0
    result: list[int] = []
    maximum = (1 << to_bits) - 1
    for value in values:
        if value < 0 or value >> from_bits:
            raise Bech32Error(f"value {value} does not fit in {from_bits} bits")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & maximum)
    if pad:
        if bits:
            result.append((accumulator << (to_bits - bits)) & maximum)
    elif bits >= from_bits or (accumulator << (to_bits - bits)) & maximum:
        raise Bech32Error("bech32 data has invalid padding")
    return result


def _check_program(witness_version: int, program: bytes) -> None:
    if not 0 <= witness_version <= 16:
        raise Bech32Error(f"witness version {witness_version} is out of range")
    if not 2 <= len(program) <= 40:
        raise Bech32Error(f"witness program must be 2 to 40 bytes, got {len(program)}")
    if witness_version == 0 and len(program) not in (20, 32):
        raise Bech32Error(
            f"a version 0 witness program must be 20 or 32 bytes, got {len(program)}"
        )


def encode(hrp: str, witness_version: int, program: bytes) -> str:
    """Encode a witness program under the human-readable part *hrp*."""
    _check_program(witness_version, program)
    data = [witness_version] + _convert_bits(program, 8, 5, pad=True)
    polymod = _polymod(_expand(hrp) + data + [0] * _CHECKSUM_LENGTH) ^ _checksum_constant(
        witness_version
    )
    checksum = [
        (polymod >> 5 * (_CHECKSUM_LENGTH - 1 - index)) & 31
        for index in range(_CHECKSUM_LENGTH)
    ]
    address = hrp + "1" + "".join(CHARSET[value] for value in data + checksum)
    if len(address) > _MAX_LENGTH:
        raise Bech32Error("address is longer than 90 characters")
    return address


def decode(hrp: str, address: str) -> tuple[int, bytes]:
    """Return the witness version and program carried by *address*."""
    if len(address) > _MAX_LENGTH:
        raise Bech32Error("address is longer than 90 characters")
    if address.lower() != address and address.upper() != address:
        raise Bech32Error("address mixes upper and lower case")
    text = address.lower()
    separator = text.rfind("1")
    if separator < 1:
        raise Bech32Error("address has no human-readable part")
    if text[:separator] != hrp.lower():
        raise Bech32Error(f"expected prefix {hrp!r}, got {text[:separator]!r}")
    values: list[int] = []
    for character in text[separator + 1 :]:
        position = CHARSET.find(character)
        if position < 0:
            raise Bech32Error(f"invalid bech32 character {character!r}")
        values.append(position)
    if len(values) <= _CHECKSUM_LENGTH:
        raise Bech32Error("address is too short to carry a checksum")
    witness_version = values[0]
    if _polymod(_expand(text[:separator]) + values) != _checksum_constant(witness_version):
        raise Bech32Error("bech32 checksum mismatch")
    program = bytes(_convert_bits(values[1:-_CHECKSUM_LENGTH], 5, 8, pad=False))
    _check_program(witness_version, program)
    return witness_version, program
