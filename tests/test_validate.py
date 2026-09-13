"""Validation must say which way an address failed, not just that it did."""

from __future__ import annotations

import pytest

from chain_addresses import (
    ENCODERS,
    Network,
    Reason,
    get_encoder,
    validate_address,
)
from chain_addresses.base58 import b58check_encode
from chain_addresses.bech32 import encode as bech32_encode
from chain_addresses.secp256k1 import compress, point_from_scalar

KEY = compress(point_from_scalar(1))
MAINNET_P2PKH = get_encoder("bitcoin-p2pkh").encode(KEY)
TESTNET_P2PKH = get_encoder("bitcoin-testnet-p2pkh").encode(KEY)
MAINNET_P2WPKH = get_encoder("bitcoin-p2wpkh").encode(KEY)
TESTNET_P2WPKH = get_encoder("bitcoin-testnet-p2wpkh").encode(KEY)
EVM = get_encoder("evm").encode(KEY)

# A published EIP-55 vector, so the mixed case below is known to be canonical.
EIP55 = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def expected_network(name: str) -> Network:
    if name == "evm":
        return Network.ANY
    return Network.TESTNET if "testnet" in name else Network.MAINNET


@pytest.mark.parametrize("name", sorted(ENCODERS))
def test_every_encoder_produces_an_address_that_validates(name: str) -> None:
    result = validate_address(ENCODERS[name].encode(KEY))
    assert result
    assert result.format == name
    assert result.network is expected_network(name)
    assert result.reason is None


@pytest.mark.parametrize("name", sorted(ENCODERS))
def test_an_address_passes_its_own_network(name: str) -> None:
    network = expected_network(name)
    requested = Network.MAINNET if network is Network.ANY else network
    assert validate_address(ENCODERS[name].encode(KEY), network=requested)


def test_a_mainnet_address_on_testnet_is_a_network_failure() -> None:
    result = validate_address(MAINNET_P2PKH, network="testnet")
    assert not result
    assert result.reason is Reason.WRONG_NETWORK
    assert result.format == "bitcoin-p2pkh"
    assert result.network is Network.MAINNET


def test_a_testnet_bech32_address_on_mainnet_is_a_network_failure() -> None:
    result = validate_address(TESTNET_P2WPKH, network=Network.MAINNET)
    assert result.reason is Reason.WRONG_NETWORK
    assert result.format == "bitcoin-testnet-p2wpkh"
    assert result.network is Network.TESTNET


def test_a_broken_checksum_is_not_reported_as_a_network_failure() -> None:
    tampered = TESTNET_P2PKH[:-1] + ("2" if TESTNET_P2PKH[-1] != "2" else "3")
    result = validate_address(tampered, network="mainnet")
    assert result.reason is Reason.BAD_CHECKSUM
    assert result.format is None


def test_a_tampered_bech32_checksum_is_caught() -> None:
    tampered = MAINNET_P2WPKH[:-1] + ("q" if MAINNET_P2WPKH[-1] != "q" else "p")
    result = validate_address(tampered)
    assert result.reason is Reason.BAD_CHECKSUM
    assert result.network is Network.MAINNET


def test_an_uppercase_bech32_address_is_accepted() -> None:
    result = validate_address(MAINNET_P2WPKH.upper())
    assert result
    assert result.format == "bitcoin-p2wpkh"


def test_a_mixed_case_bech32_address_is_malformed() -> None:
    mixed = MAINNET_P2WPKH[:4].upper() + MAINNET_P2WPKH[4:]
    assert validate_address(mixed).reason is Reason.MALFORMED


def test_a_script_hash_output_validates_even_though_no_encoder_makes_one() -> None:
    result = validate_address(bech32_encode("bc", 0, bytes(32)))
    assert result
    assert result.format == "bitcoin-p2wsh"


def test_a_future_witness_version_is_unsupported_rather_than_broken() -> None:
    result = validate_address(bech32_encode("tb", 2, bytes(32)))
    assert result.reason is Reason.UNSUPPORTED_FORMAT
    assert result.network is Network.TESTNET


def test_an_unknown_base58_version_is_unsupported() -> None:
    result = validate_address(b58check_encode(b"\x1f" + bytes(20)))
    assert result.reason is Reason.UNSUPPORTED_FORMAT
    assert "0x1f" in result.detail


def test_an_extended_key_is_not_an_address() -> None:
    text = b58check_encode(b"\x04\x88\xb2\x1e" + bytes(74))
    result = validate_address(text)
    assert result.reason is Reason.MALFORMED
    assert "extended key" in result.detail


def test_eip55_hex_validates_and_belongs_to_no_single_network() -> None:
    result = validate_address(EIP55)
    assert result
    assert result.format == "evm"
    assert result.network is Network.ANY


@pytest.mark.parametrize("network", ["mainnet", "testnet"])
def test_an_evm_address_passes_on_any_network(network: str) -> None:
    assert validate_address(EVM, network=network)


def test_single_case_hex_is_accepted_without_a_checksum_to_check() -> None:
    result = validate_address(EIP55.lower())
    assert result
    assert "no EIP-55 checksum" in result.detail


def test_wrong_eip55_case_is_a_checksum_failure() -> None:
    tampered = EIP55[:3] + "A" + EIP55[4:]
    result = validate_address(tampered)
    assert result.reason is Reason.BAD_CHECKSUM
    assert result.format == "evm"


@pytest.mark.parametrize("address", ["0x", "0x" + "a" * 39, "0x" + "g" * 40])
def test_a_half_written_hex_address_is_malformed(address: str) -> None:
    assert validate_address(address).reason is Reason.MALFORMED


@pytest.mark.parametrize("address", ["hello world", "ltc1qqqqqqqq", "!!!"])
def test_a_foreign_string_is_an_unknown_format(address: str) -> None:
    assert validate_address(address).reason is Reason.UNKNOWN_FORMAT


def test_an_empty_address_is_malformed() -> None:
    assert validate_address("   ").reason is Reason.MALFORMED


def test_surrounding_whitespace_is_ignored() -> None:
    assert validate_address(f"  {MAINNET_P2PKH}\n")


def test_a_format_filter_rejects_a_valid_address_of_another_kind() -> None:
    result = validate_address(MAINNET_P2PKH, formats=["bitcoin-p2wpkh"])
    assert result.reason is Reason.WRONG_FORMAT
    assert result.format == "bitcoin-p2pkh"
    assert validate_address(MAINNET_P2WPKH, formats=["bitcoin-p2wpkh"])


def test_an_unknown_network_name_is_rejected() -> None:
    with pytest.raises(ValueError):
        validate_address(MAINNET_P2PKH, network="regtest")
