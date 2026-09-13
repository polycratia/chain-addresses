"""Check an address before sending to it, with a typed reason when it fails.

A rejection is only useful if the caller can tell the cases apart: a well-formed
mainnet address in a testnet flow is a configuration mistake, a failed checksum
is a typo or a truncated copy, and an unrecognised string is neither. Every
check returns a :class:`ValidationResult` carrying a :class:`Reason`, so callers
branch on a value instead of matching on message text.

Validation covers a little more than encoding does: a v0 32-byte witness program
(P2WSH) is a fine destination even though no encoder here produces one.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import Enum

from . import bech32
from .addresses import to_checksum_address
from .base58 import ALPHABET as _BASE58_ALPHABET
from .base58 import b58check_decode
from .errors import Base58Error, Bech32Error, ChainAddressesError

__all__ = ["Network", "Reason", "ValidationResult", "validate_address"]

_HEX_DIGITS = frozenset("0123456789abcdef")
_BASE58_CHARACTERS = frozenset(_BASE58_ALPHABET)
_PAYLOAD_LENGTH = 21
_EXTENDED_KEY_LENGTH = 78


class Network(str, Enum):
    """Which chain an address belongs to; ``ANY`` carries no network marker."""

    MAINNET = "mainnet"
    TESTNET = "testnet"
    ANY = "any"


class Reason(str, Enum):
    """Why an address was rejected."""

    UNKNOWN_FORMAT = "unknown_format"
    MALFORMED = "malformed"
    BAD_CHECKSUM = "bad_checksum"
    UNSUPPORTED_FORMAT = "unsupported_format"
    WRONG_NETWORK = "wrong_network"
    WRONG_FORMAT = "wrong_format"


@dataclass(frozen=True)
class ValidationResult:
    """The verdict on one address, truthy when the address may be used."""

    address: str
    ok: bool
    format: str | None = None
    network: Network | None = None
    reason: Reason | None = None
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


_BASE58_VERSIONS: dict[int, tuple[str, Network]] = {
    0x00: ("p2pkh", Network.MAINNET),
    0x05: ("p2sh", Network.MAINNET),
    0x6F: ("p2pkh", Network.TESTNET),
    0xC4: ("p2sh", Network.TESTNET),
}

_HRP_NETWORKS: dict[str, Network] = {"bc": Network.MAINNET, "tb": Network.TESTNET}

_WITNESS_KINDS: dict[tuple[int, int], str] = {
    (0, 20): "p2wpkh",
    (0, 32): "p2wsh",
    (1, 32): "p2tr",
}


def _name(kind: str, network: Network) -> str:
    prefix = "bitcoin-" if network is Network.MAINNET else "bitcoin-testnet-"
    return prefix + kind


def _ok(address: str, name: str, network: Network, detail: str = "") -> ValidationResult:
    return ValidationResult(
        address=address, ok=True, format=name, network=network, detail=detail
    )


def _fail(
    address: str,
    reason: Reason,
    detail: str,
    *,
    name: str | None = None,
    network: Network | None = None,
) -> ValidationResult:
    return ValidationResult(
        address=address,
        ok=False,
        format=name,
        network=network,
        reason=reason,
        detail=detail,
    )


def _reason_for(error: ChainAddressesError) -> Reason:
    # Both decoders end a checksum failure with this phrase; every other message
    # they raise describes a structural problem in the string itself.
    if str(error).endswith("checksum mismatch"):
        return Reason.BAD_CHECKSUM
    return Reason.MALFORMED


def _is_hex(text: str) -> bool:
    return bool(text) and set(text.lower()) <= _HEX_DIGITS


def _inspect_evm(address: str, body: str) -> ValidationResult:
    if len(body) != 40 or not _is_hex(body):
        return _fail(
            address,
            Reason.MALFORMED,
            f"an EVM address is 40 hex digits, got {len(body)}",
        )
    mixed_case = body.lower() != body and body.upper() != body
    if mixed_case and to_checksum_address(body) != "0x" + body:
        return _fail(
            address,
            Reason.BAD_CHECKSUM,
            "EIP-55 checksum mismatch",
            name="evm",
            network=Network.ANY,
        )
    detail = "" if mixed_case else "single-case hex carries no EIP-55 checksum"
    return _ok(address, "evm", Network.ANY, detail)


def _inspect_bech32(address: str, hrp: str) -> ValidationResult:
    network = _HRP_NETWORKS[hrp]
    try:
        witness_version, program = bech32.decode(hrp, address)
    except Bech32Error as error:
        return _fail(address, _reason_for(error), str(error), network=network)
    kind = _WITNESS_KINDS.get((witness_version, len(program)))
    if kind is None:
        return _fail(
            address,
            Reason.UNSUPPORTED_FORMAT,
            f"witness version {witness_version} with a {len(program)}-byte program "
            "is not an address format this package knows",
            network=network,
        )
    return _ok(address, _name(kind, network), network)


def _inspect_base58(address: str) -> ValidationResult:
    try:
        payload = b58check_decode(address)
    except Base58Error as error:
        return _fail(address, _reason_for(error), str(error))
    if len(payload) != _PAYLOAD_LENGTH:
        detail = (
            f"Base58Check payload is {len(payload)} bytes, "
            f"expected {_PAYLOAD_LENGTH}"
        )
        if len(payload) == _EXTENDED_KEY_LENGTH:
            detail += "; this is an extended key, not an address"
        return _fail(address, Reason.MALFORMED, detail)
    entry = _BASE58_VERSIONS.get(payload[0])
    if entry is None:
        return _fail(
            address,
            Reason.UNSUPPORTED_FORMAT,
            f"unknown Base58Check version byte {payload[0]:#04x}",
        )
    kind, network = entry
    return _ok(address, _name(kind, network), network)


def _inspect(address: str) -> ValidationResult:
    if not address:
        return _fail(address, Reason.MALFORMED, "empty address")
    if address[:2].lower() == "0x":
        return _inspect_evm(address, address[2:])
    if len(address) == 40 and _is_hex(address):
        return _inspect_evm(address, address)
    lowered = address.lower()
    separator = lowered.rfind("1")
    if separator > 0 and lowered[:separator] in _HRP_NETWORKS:
        return _inspect_bech32(address, lowered[:separator])
    if set(address) <= _BASE58_CHARACTERS:
        return _inspect_base58(address)
    return _fail(
        address,
        Reason.UNKNOWN_FORMAT,
        "not a Base58Check, bech32 or hex address",
    )


def validate_address(
    address: str,
    *,
    network: Network | str | None = None,
    formats: Iterable[str] | None = None,
) -> ValidationResult:
    """Validate *address* and report the first reason it cannot be used.

    Encoding is checked before anything else, so a corrupted testnet address is
    a checksum failure rather than a network mismatch. ``network`` rejects an
    address that belongs to another chain, and ``formats`` limits the accepted
    formats to the given names.
    """
    expected = Network(network) if network is not None else None
    result = _inspect(address.strip())
    if not result.ok:
        return result
    if expected is not None and expected is not Network.ANY:
        if result.network is not Network.ANY and result.network is not expected:
            return replace(
                result,
                ok=False,
                reason=Reason.WRONG_NETWORK,
                detail=f"address belongs to {result.network.value}, "
                f"not {expected.value}",
            )
    if formats is not None:
        accepted = set(formats)
        if result.format not in accepted:
            return replace(
                result,
                ok=False,
                reason=Reason.WRONG_FORMAT,
                detail=f"address is {result.format}, expected one of: "
                + ", ".join(sorted(accepted)),
            )
    return result
