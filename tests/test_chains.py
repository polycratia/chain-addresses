"""Every encoder name must say which chain it serves and which path it sits under."""

from __future__ import annotations

import pytest

from chain_addresses import (
    CHAINS,
    ENCODERS,
    HARDENED_OFFSET,
    ChainError,
    ChainInfo,
    Network,
    account_path,
    chain_info,
    formats_for,
)

# BIP44, BIP49, BIP84 and BIP86 each fix the purpose level of one output format.
PURPOSES = {"p2pkh": 44, "p2sh": 49, "p2wpkh": 84, "p2tr": 86}

ACCOUNT_PATHS = {
    "bitcoin-p2pkh": "m/44'/0'/0'",
    "bitcoin-p2sh": "m/49'/0'/0'",
    "bitcoin-p2wpkh": "m/84'/0'/0'",
    "bitcoin-p2tr": "m/86'/0'/0'",
    "bitcoin-testnet-p2pkh": "m/44'/1'/0'",
    "bitcoin-testnet-p2sh": "m/49'/1'/0'",
    "bitcoin-testnet-p2wpkh": "m/84'/1'/0'",
    "bitcoin-testnet-p2tr": "m/86'/1'/0'",
    "evm": "m/44'/60'/0'",
}

MAINNET_FORMATS = (
    "bitcoin-p2pkh",
    "bitcoin-p2sh",
    "bitcoin-p2wpkh",
    "bitcoin-p2tr",
)
TESTNET_FORMATS = (
    "bitcoin-testnet-p2pkh",
    "bitcoin-testnet-p2sh",
    "bitcoin-testnet-p2wpkh",
    "bitcoin-testnet-p2tr",
)


def test_every_encoder_name_carries_chain_metadata() -> None:
    assert set(CHAINS) == set(ENCODERS)


def test_the_registry_is_consistent() -> None:
    assert all(name == info.name for name, info in CHAINS.items())
    assert all(isinstance(info, ChainInfo) for info in CHAINS.values())


def test_the_expected_paths_cover_every_encoder() -> None:
    assert set(ACCOUNT_PATHS) == set(ENCODERS)


@pytest.mark.parametrize(("name", "path"), sorted(ACCOUNT_PATHS.items()))
def test_account_path_follows_the_bip_of_the_format(name: str, path: str) -> None:
    assert account_path(name) == path
    assert chain_info(name).account_path() == path


@pytest.mark.parametrize("name", sorted(ENCODERS))
def test_every_account_path_is_hardened_to_three_levels(name: str) -> None:
    path = account_path(name)
    assert path.startswith("m/")
    elements = path[2:].split("/")
    assert len(elements) == 3
    assert all(element.endswith("'") for element in elements)


@pytest.mark.parametrize("name", sorted(ENCODERS))
def test_the_purpose_matches_the_output_format(name: str) -> None:
    info = chain_info(name)
    expected = 44 if name == "evm" else PURPOSES[name.rsplit("-", 1)[1]]
    assert info.purpose == expected


@pytest.mark.parametrize("name", sorted(ENCODERS))
def test_the_network_matches_the_encoder_name(name: str) -> None:
    info = chain_info(name)
    if name == "evm":
        assert info.network is Network.ANY
    elif "testnet" in name:
        assert info.network is Network.TESTNET
    else:
        assert info.network is Network.MAINNET


def test_the_coin_type_follows_the_network_not_the_format() -> None:
    assert {chain_info(name).coin_type for name in MAINNET_FORMATS} == {0}
    assert {chain_info(name).coin_type for name in TESTNET_FORMATS} == {1}
    assert chain_info("evm").coin_type == 60


@pytest.mark.parametrize("account", [0, 1, 5, HARDENED_OFFSET - 1])
def test_a_later_account_moves_only_the_last_level(account: int) -> None:
    assert account_path("bitcoin-p2wpkh", account) == f"m/84'/0'/{account}'"


@pytest.mark.parametrize("account", [-1, HARDENED_OFFSET, 2**32])
def test_an_account_outside_the_hardened_range_is_rejected(account: int) -> None:
    with pytest.raises(ChainError, match="account"):
        account_path("bitcoin-p2wpkh", account)


def test_formats_for_lists_one_network_without_the_other() -> None:
    assert formats_for("bitcoin", "testnet") == TESTNET_FORMATS
    assert formats_for("bitcoin", Network.MAINNET) == MAINNET_FORMATS


def test_formats_for_without_a_network_lists_both() -> None:
    assert formats_for("bitcoin") == MAINNET_FORMATS + TESTNET_FORMATS


@pytest.mark.parametrize("network", [None, "mainnet", "testnet", Network.ANY])
def test_evm_hex_belongs_to_every_network(network: Network | str | None) -> None:
    assert formats_for("evm", network) == ("evm",)


def test_every_format_is_listed_by_its_own_chain() -> None:
    chains = dict.fromkeys(info.chain for info in CHAINS.values())
    listed = [name for chain in chains for name in formats_for(chain)]
    assert sorted(listed) == sorted(ENCODERS)


def test_the_bitcoin_formats_are_every_name_but_the_evm_one() -> None:
    assert set(formats_for("bitcoin")) == set(ENCODERS) - {"evm"}


def test_an_unknown_chain_is_rejected() -> None:
    with pytest.raises(ChainError, match="unknown chain"):
        formats_for("litecoin")


def test_an_unknown_format_is_rejected() -> None:
    with pytest.raises(ChainError, match="unknown address format"):
        chain_info("bitcoin-p2unknown")


def test_an_unknown_network_name_is_rejected() -> None:
    with pytest.raises(ValueError):
        formats_for("bitcoin", "regtest")
