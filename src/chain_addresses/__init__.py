"""Deposit address derivation across chains from extended public keys."""

from .addresses import (
    ENCODERS,
    AddressEncoder,
    EvmAddress,
    P2PKH,
    P2SHP2WPKH,
    P2TR,
    P2WPKH,
    get_encoder,
    to_checksum_address,
)
from .bip32 import HARDENED_OFFSET, ExtendedPublicKey, hash160, parse_path
from .errors import (
    AddressError,
    Base58Error,
    Bech32Error,
    ChainAddressesError,
    DerivationError,
    ExtendedKeyError,
    GapLimitError,
    LedgerError,
)
from .gap import DEFAULT_GAP_LIMIT, AddressLedger, DepositAddress
from .validate import Network, Reason, ValidationResult, validate_address

__version__ = "0.1.0"

__all__ = [
    "AddressEncoder",
    "AddressError",
    "AddressLedger",
    "Base58Error",
    "Bech32Error",
    "ChainAddressesError",
    "DEFAULT_GAP_LIMIT",
    "DepositAddress",
    "DerivationError",
    "ENCODERS",
    "EvmAddress",
    "ExtendedKeyError",
    "ExtendedPublicKey",
    "GapLimitError",
    "HARDENED_OFFSET",
    "LedgerError",
    "Network",
    "P2PKH",
    "P2SHP2WPKH",
    "P2TR",
    "P2WPKH",
    "Reason",
    "ValidationResult",
    "get_encoder",
    "hash160",
    "parse_path",
    "to_checksum_address",
    "validate_address",
    "__version__",
]
