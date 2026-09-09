"""One address interface for every supported chain.

A caller derives a child public key and hands it to an encoder looked up by
name; whether that becomes Base58Check, bech32, bech32m or EIP-55 hex stays
inside this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from . import bech32
from .base58 import b58check_encode
from .bip32 import hash160
from .errors import AddressError
from .keccak import keccak256
from .secp256k1 import (
    CURVE_ORDER,
    FIELD_PRIME,
    Point,
    decompress,
    point_add,
    point_from_scalar,
)

__all__ = [
    "ENCODERS",
    "AddressEncoder",
    "EvmAddress",
    "P2PKH",
    "P2SHP2WPKH",
    "P2TR",
    "P2WPKH",
    "get_encoder",
    "to_checksum_address",
]

_HEX_DIGITS = frozenset("0123456789abcdef")


@runtime_checkable
class AddressEncoder(Protocol):
    """Turns a compressed public key into an address for one chain and format."""

    name: str

    def encode(self, public_key: bytes) -> str:
        """Return the address for the 33-byte compressed *public_key*."""
        ...


def _point(public_key: bytes) -> Point:
    try:
        return decompress(public_key)
    except ValueError as error:
        raise AddressError(f"invalid compressed public key: {error}") from error


def _key_hash(public_key: bytes) -> bytes:
    _point(public_key)
    return hash160(public_key)


def _tagged_hash(tag: str, message: bytes) -> bytes:
    prefix = sha256(tag.encode("ascii")).digest()
    return sha256(prefix + prefix + message).digest()


def _taproot_output_key(public_key: bytes) -> bytes:
    x, y = _point(public_key)
    if y % 2:
        # Taproot keys are x-only, so the internal key is always the even-y point.
        y = FIELD_PRIME - y
    tweak = int.from_bytes(_tagged_hash("TapTweak", x.to_bytes(32, "big")), "big")
    if not 0 < tweak < CURVE_ORDER:
        raise AddressError("taproot tweak is outside the curve order")
    output = point_add((x, y), point_from_scalar(tweak))
    if output is None:
        raise AddressError("taproot tweak cancelled the internal key")
    return output[0].to_bytes(32, "big")


def to_checksum_address(address: str) -> str:
    """Return *address* with the EIP-55 mixed-case checksum applied."""
    body = address[2:] if address[:2].lower() == "0x" else address
    lowered = body.lower()
    if len(lowered) != 40 or not set(lowered) <= _HEX_DIGITS:
        raise AddressError(f"{address!r} is not a 20-byte hex address")
    digest = keccak256(lowered.encode("ascii")).hex()
    return "0x" + "".join(
        character.upper() if int(digest[position], 16) >= 8 else character
        for position, character in enumerate(lowered)
    )


@dataclass(frozen=True)
class P2PKH:
    """Pay to public key hash: Base58Check over a versioned HASH160."""

    name: str
    version: int

    def encode(self, public_key: bytes) -> str:
        return b58check_encode(bytes([self.version]) + _key_hash(public_key))


@dataclass(frozen=True)
class P2SHP2WPKH:
    """A P2WPKH program wrapped in P2SH, the P2SH form a single key can produce."""

    name: str
    version: int

    def encode(self, public_key: bytes) -> str:
        redeem_script = b"\x00\x14" + _key_hash(public_key)
        return b58check_encode(bytes([self.version]) + hash160(redeem_script))


@dataclass(frozen=True)
class P2WPKH:
    """Native segwit v0: bech32 over the key hash."""

    name: str
    hrp: str

    def encode(self, public_key: bytes) -> str:
        return bech32.encode(self.hrp, 0, _key_hash(public_key))


@dataclass(frozen=True)
class P2TR:
    """Taproot: bech32m over the BIP86 key-path tweak of the internal key."""

    name: str
    hrp: str

    def encode(self, public_key: bytes) -> str:
        return bech32.encode(self.hrp, 1, _taproot_output_key(public_key))


@dataclass(frozen=True)
class EvmAddress:
    """EIP-55 checksummed hex, shared by every EVM chain."""

    name: str

    def encode(self, public_key: bytes) -> str:
        x, y = _point(public_key)
        digest = keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))
        return to_checksum_address(digest[-20:].hex())


_ALL: tuple[AddressEncoder, ...] = (
    P2PKH("bitcoin-p2pkh", 0x00),
    P2SHP2WPKH("bitcoin-p2sh", 0x05),
    P2WPKH("bitcoin-p2wpkh", "bc"),
    P2TR("bitcoin-p2tr", "bc"),
    P2PKH("bitcoin-testnet-p2pkh", 0x6F),
    P2SHP2WPKH("bitcoin-testnet-p2sh", 0xC4),
    P2WPKH("bitcoin-testnet-p2wpkh", "tb"),
    P2TR("bitcoin-testnet-p2tr", "tb"),
    EvmAddress("evm"),
)

ENCODERS: Mapping[str, AddressEncoder] = MappingProxyType(
    {encoder.name: encoder for encoder in _ALL}
)


def get_encoder(name: str) -> AddressEncoder:
    """Return the encoder registered under *name*."""
    try:
        return ENCODERS[name]
    except KeyError:
        known = ", ".join(ENCODERS)
        raise AddressError(f"unknown address format {name!r}; known: {known}") from None
