"""Exceptions raised while parsing extended keys or deriving children."""

from __future__ import annotations

__all__ = [
    "Base58Error",
    "ChainAddressesError",
    "DerivationError",
    "ExtendedKeyError",
]


class ChainAddressesError(Exception):
    """Base class for every error raised by this package."""


class Base58Error(ChainAddressesError):
    """Raised when a Base58Check string is malformed or fails its checksum."""


class ExtendedKeyError(ChainAddressesError):
    """Raised when an extended key cannot be parsed or is not a public key."""


class DerivationError(ChainAddressesError):
    """Raised when a derivation path cannot be walked from a public key."""
