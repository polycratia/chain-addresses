"""Which chain, network and BIP levels sit behind every encoder name.

An encoder name says how an address is written, not where the key it encodes
came from, and the two cannot be picked independently: the purpose level of the
path is what tells a signer which output format an account holds. A key
exported from ``m/44'/0'/0'`` is scanned for Base58 addresses, so encoding its
children as ``bc1`` produces addresses the wallet behind that account will
never look for.

The registry below keeps that metadata beside the encoder names, so a caller
offering a format can also say which account path it belongs under. Only the
hardened account prefix is given; the branch and index below it are the
ledger's business and stay out of here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .bip32 import HARDENED_OFFSET
from .errors import ChainError
from .validate import Network

__all__ = [
    "CHAINS",
    "ChainInfo",
    "account_path",
    "chain_info",
    "formats_for",
]


@dataclass(frozen=True)
class ChainInfo:
    """The chain, network and BIP derivation levels behind one encoder name."""

    name: str
    chain: str
    network: Network
    purpose: int
    coin_type: int

    def account_path(self, account: int = 0) -> str:
        """The hardened account path keys for this format are derived under."""
        if not 0 <= account < HARDENED_OFFSET:
            raise ChainError(
                f"account {account} is outside the hardened index range"
            )
        return f"m/{self.purpose}'/{self.coin_type}'/{account}'"


_ALL: tuple[ChainInfo, ...] = (
    ChainInfo("bitcoin-p2pkh", "bitcoin", Network.MAINNET, 44, 0),
    ChainInfo("bitcoin-p2sh", "bitcoin", Network.MAINNET, 49, 0),
    ChainInfo("bitcoin-p2wpkh", "bitcoin", Network.MAINNET, 84, 0),
    ChainInfo("bitcoin-p2tr", "bitcoin", Network.MAINNET, 86, 0),
    ChainInfo("bitcoin-testnet-p2pkh", "bitcoin", Network.TESTNET, 44, 1),
    ChainInfo("bitcoin-testnet-p2sh", "bitcoin", Network.TESTNET, 49, 1),
    ChainInfo("bitcoin-testnet-p2wpkh", "bitcoin", Network.TESTNET, 84, 1),
    ChainInfo("bitcoin-testnet-p2tr", "bitcoin", Network.TESTNET, 86, 1),
    ChainInfo("evm", "evm", Network.ANY, 44, 60),
)

CHAINS: Mapping[str, ChainInfo] = MappingProxyType({info.name: info for info in _ALL})

_CHAIN_NAMES: tuple[str, ...] = tuple(dict.fromkeys(info.chain for info in _ALL))


def chain_info(name: str) -> ChainInfo:
    """Return the chain metadata registered for the encoder *name*."""
    try:
        return CHAINS[name]
    except KeyError:
        known = ", ".join(CHAINS)
        raise ChainError(
            f"unknown address format {name!r}; known: {known}"
        ) from None


def account_path(name: str, account: int = 0) -> str:
    """The account path the format *name* belongs under, for example ``m/84'/1'/0'``."""
    return chain_info(name).account_path(account)


def formats_for(chain: str, network: Network | str | None = None) -> tuple[str, ...]:
    """The encoder names registered for *chain*, narrowed to *network* when given.

    A format that carries no network marker, as EVM hex does, is listed for
    every network asked for.
    """
    if chain not in _CHAIN_NAMES:
        known = ", ".join(_CHAIN_NAMES)
        raise ChainError(f"unknown chain {chain!r}; known: {known}")
    expected = Network(network) if network is not None else None
    return tuple(
        info.name
        for info in CHAINS.values()
        if info.chain == chain
        and (
            expected is None
            or expected is Network.ANY
            or info.network is Network.ANY
            or info.network is expected
        )
    )
