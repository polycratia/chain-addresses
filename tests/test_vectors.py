"""Specification test vectors: BIP32, BIP84 and EIP-55.

Every value below is published, not produced by this package. The rest of the
suite checks that the code is consistent with itself; these tests fail when it
drifts from the standards it claims to implement.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from chain_addresses import (
    DerivationError,
    ExtendedPublicKey,
    Network,
    get_encoder,
    hash160,
    to_checksum_address,
    validate_address,
)
from chain_addresses.bech32 import decode as bech32_decode

# BIP32 test vector 1, seed 000102030405060708090a0b0c0d0e0f.
BIP32_MASTER = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJ"
    "oCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)  # m
BIP32_ACCOUNT = (
    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK"
    "1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
)  # m/0'
BIP32_CHILD = (
    "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiG"
    "j7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
)  # m/0'/1

_ZPUB_VERSION = 0x04B24746

# BIP84 test vectors: addresses of the account m/84'/0'/0' of the test mnemonic.
BIP84 = [
    pytest.param(
        "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        id="84h/0h/0h/0/0",
    ),
    pytest.param(
        "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77",
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        id="84h/0h/0h/0/1",
    ),
    pytest.param(
        "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6",
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        id="84h/0h/0h/1/0",
    ),
]

# EIP-55 test cases, in the three case patterns the specification lists.
EIP55 = [
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]


@pytest.mark.parametrize("text", [BIP32_MASTER, BIP32_ACCOUNT, BIP32_CHILD])
def test_a_published_key_survives_parsing_and_serialisation(text: str) -> None:
    key = ExtendedPublicKey.parse(text)
    assert key.serialize() == text
    assert ExtendedPublicKey.parse(key.serialize()) == key


def test_the_master_key_is_published_at_depth_zero() -> None:
    master = ExtendedPublicKey.parse(BIP32_MASTER)
    assert master.prefix == "xpub"
    assert master.depth == 0
    assert master.parent_fingerprint == b"\x00\x00\x00\x00"
    assert master.child_number == 0


def test_the_account_key_records_the_hardened_index_behind_it() -> None:
    account = ExtendedPublicKey.parse(BIP32_ACCOUNT)
    assert account.depth == 1
    assert account.child_number == 0x80000000
    assert account.parent_fingerprint == ExtendedPublicKey.parse(
        BIP32_MASTER
    ).fingerprint


def test_ckdpub_reaches_the_published_child() -> None:
    account = ExtendedPublicKey.parse(BIP32_ACCOUNT)
    assert account.child(1).serialize() == BIP32_CHILD
    assert account.derive("1").serialize() == BIP32_CHILD


def test_the_published_child_points_back_at_the_account_key() -> None:
    account = ExtendedPublicKey.parse(BIP32_ACCOUNT)
    child = ExtendedPublicKey.parse(BIP32_CHILD)
    assert child.depth == 2
    assert child.child_number == 1
    assert child.parent_fingerprint == account.fingerprint


def test_the_hardened_step_of_the_vector_is_out_of_reach() -> None:
    # m -> m/0' is why the vector has to be picked up again at the account key.
    with pytest.raises(DerivationError):
        ExtendedPublicKey.parse(BIP32_MASTER).derive("0'")


@pytest.mark.parametrize(("public_key", "address"), BIP84)
def test_bip84_keys_encode_to_the_published_addresses(
    public_key: str, address: str
) -> None:
    assert get_encoder("bitcoin-p2wpkh").encode(bytes.fromhex(public_key)) == address


@pytest.mark.parametrize(("public_key", "address"), BIP84)
def test_a_published_address_decodes_back_to_its_key_hash(
    public_key: str, address: str
) -> None:
    assert bech32_decode("bc", address) == (0, hash160(bytes.fromhex(public_key)))
    result = validate_address(address)
    assert result
    assert result.format == "bitcoin-p2wpkh"
    assert result.network is Network.MAINNET


def test_the_bip84_prefix_changes_the_string_and_not_the_derivation() -> None:
    # BIP84 publishes account keys as zpub: the version byte is serialisation only.
    xpub = ExtendedPublicKey.parse(BIP32_ACCOUNT)
    zpub = replace(xpub, version=_ZPUB_VERSION)
    assert zpub.prefix == "zpub"
    assert zpub.serialize().startswith("zpub")
    assert zpub.child(1).public_key == xpub.child(1).public_key


@pytest.mark.parametrize("address", EIP55)
def test_eip55_checksums_the_published_addresses(address: str) -> None:
    assert to_checksum_address(address.lower()) == address
    assert to_checksum_address(address[2:]) == address
    assert to_checksum_address(address) == address


@pytest.mark.parametrize("address", EIP55)
def test_a_published_eip55_address_validates(address: str) -> None:
    result = validate_address(address)
    assert result
    assert result.format == "evm"
    assert result.network is Network.ANY
