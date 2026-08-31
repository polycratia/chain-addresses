"""Deposit address derivation across chains from extended public keys."""

from .bip32 import HARDENED_OFFSET, ExtendedPublicKey, hash160, parse_path
from .errors import (
    Base58Error,
    ChainAddressesError,
    DerivationError,
    ExtendedKeyError,
)

__version__ = "0.1.0"

__all__ = [
    "Base58Error",
    "ChainAddressesError",
    "DerivationError",
    "ExtendedKeyError",
    "ExtendedPublicKey",
    "HARDENED_OFFSET",
    "hash160",
    "parse_path",
    "__version__",
]
