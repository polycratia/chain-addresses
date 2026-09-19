"""Every address format, from one compressed public key."""

from __future__ import annotations

import pytest

from chain_addresses import (
    ENCODERS,
    AddressEncoder,
    AddressError,
    ExtendedPublicKey,
    get_encoder,
    hash160,
    to_checksum_address,
)
from chain_addresses.base58 import b58check_decode
from chain_addresses.bech32 import decode as bech32_decode
from chain_addresses.secp256k1 import compress, point_from_scalar

# The generator, whose HASH160 is the key hash used by the BIP173 examples.
KEY = compress(point_from_scalar(1))
KEY_HASH = hash160(KEY)


def test_p2pkh_is_a_versioned_key_hash() -> None:
    address = get_encoder("bitcoin-p2pkh").encode(KEY)
    assert address.startswith("1")
    assert b58check_decode(address) == b"\x00" + KEY_HASH


def test_testnet_p2pkh_uses_the_testnet_version() -> None:
    address = get_encoder("bitcoin-testnet-p2pkh").encode(KEY)
    assert address[0] in "mn"
    assert b58check_decode(address) == b"\x6f" + KEY_HASH


def test_p2sh_wraps_the_witness_program() -> None:
    address = get_encoder("bitcoin-p2sh").encode(KEY)
    assert address.startswith("3")
    assert b58check_decode(address) == b"\x05" + hash160(b"\x00\x14" + KEY_HASH)


def test_p2wpkh_matches_the_bip173_vector() -> None:
    expected = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert get_encoder("bitcoin-p2wpkh").encode(KEY) == expected


def test_testnet_p2wpkh_uses_the_tb_prefix() -> None:
    address = get_encoder("bitcoin-testnet-p2wpkh").encode(KEY)
    assert bech32_decode("tb", address) == (0, KEY_HASH)


def test_p2tr_matches_the_bip86_output_key() -> None:
    internal = bytes.fromhex(
        "02cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
    )
    address = get_encoder("bitcoin-p2tr").encode(internal)
    assert address.startswith("bc1p")
    version, program = bech32_decode("bc", address)
    assert version == 1
    assert program.hex() == (
        "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    )


def test_p2tr_ignores_the_parity_of_the_internal_key() -> None:
    encoder = get_encoder("bitcoin-p2tr")
    assert encoder.encode(b"\x03" + KEY[1:]) == encoder.encode(KEY)


def test_evm_address_of_a_known_key() -> None:
    address = get_encoder("evm").encode(KEY)
    assert address.lower() == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    assert to_checksum_address(address) == address


@pytest.mark.parametrize("address", ["0x", "1234", "0x" + "g" * 40, "0" * 41])
def test_checksum_rejects_non_addresses(address: str) -> None:
    with pytest.raises(AddressError):
        to_checksum_address(address)


@pytest.mark.parametrize("name", sorted(ENCODERS))
@pytest.mark.parametrize(
    "public_key",
    [b"", b"\x02" * 32, b"\x04" + b"\x11" * 32, b"\x02" + b"\xff" * 32],
)
def test_every_encoder_rejects_a_malformed_key(name: str, public_key: bytes) -> None:
    with pytest.raises(AddressError):
        ENCODERS[name].encode(public_key)


def test_unknown_formats_are_rejected() -> None:
    with pytest.raises(AddressError, match="unknown address format"):
        get_encoder("bitcoin-p2unknown")


def test_the_registry_is_consistent() -> None:
    assert all(name == encoder.name for name, encoder in ENCODERS.items())
    assert all(isinstance(encoder, AddressEncoder) for encoder in ENCODERS.values())


def test_a_derived_child_gets_one_address_per_format() -> None:
    account = ExtendedPublicKey(
        version=0x0488B21E,
        depth=0,
        parent_fingerprint=b"\x00\x00\x00\x00",
        child_number=0,
        chain_code=bytes(range(32)),
        public_key=KEY,
    )
    child = account.derive("0/17")
    addresses = {name: e.encode(child.public_key) for name, e in ENCODERS.items()}
    assert len(set(addresses.values())) == len(ENCODERS)
