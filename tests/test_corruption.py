"""A single mistyped character must never reach a different valid address.

The reason an address format carries a checksum is that a typo should be caught
rather than quietly sent somewhere else. The sweeps below make that promise
explicit: every position of a valid address is replaced by every other
character of the alphabet the address is written in, and no replacement may
validate. A string still read as the format it came from has to fail on its
checksum, and never on the network: a corrupted address of one chain must not
be reported as a well-formed address of another.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from chain_addresses import ENCODERS, Network, Reason, validate_address
from chain_addresses.base58 import ALPHABET as BASE58_ALPHABET
from chain_addresses.bech32 import CHARSET as BECH32_CHARSET
from chain_addresses.secp256k1 import compress, point_from_scalar

KEY = compress(point_from_scalar(1))

HRPS = ("bc", "tb")

BASE58_FORMATS = [
    "bitcoin-p2pkh",
    "bitcoin-p2sh",
    "bitcoin-testnet-p2pkh",
    "bitcoin-testnet-p2sh",
]
BECH32_FORMATS = [
    "bitcoin-p2wpkh",
    "bitcoin-p2tr",
    "bitcoin-testnet-p2wpkh",
    "bitcoin-testnet-p2tr",
]

# A published EIP-55 vector, so the mixed case swapped below is known canonical.
EIP55 = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def other_network(name: str) -> Network:
    """The network an address of *name* does not belong to."""
    return Network.MAINNET if "testnet" in name else Network.TESTNET


def swaps(address: str, alphabet: str) -> Iterator[tuple[int, str]]:
    """Every string one character away from *address* within *alphabet*."""
    for index in range(len(address)):
        for character in alphabet:
            if character != address[index]:
                yield index, address[:index] + character + address[index + 1 :]


def reads_as_base58(candidate: str) -> bool:
    """Whether validation still routes *candidate* to the Base58Check decoder."""
    # A Base58 address is 34 or 35 characters, too short to be read as 40 hex
    # digits, so a known hrp followed by a separator is the only other route.
    lowered = candidate.lower()
    separator = lowered.rfind("1")
    return not (separator > 0 and lowered[:separator] in HRPS)


def check(candidate: str, crossed: Network, *, in_format: bool) -> None:
    """Assert *candidate* cannot be used, under its own network and the other."""
    plain = validate_address(candidate)
    other = validate_address(candidate, network=crossed)
    assert not plain, candidate
    assert not other, candidate
    assert other.reason is not Reason.WRONG_NETWORK, candidate
    if in_format:
        assert plain.reason is Reason.BAD_CHECKSUM, candidate
        assert other.reason is Reason.BAD_CHECKSUM, candidate


@pytest.mark.parametrize("name", BASE58_FORMATS)
def test_no_single_base58_character_swap_validates(name: str) -> None:
    address = ENCODERS[name].encode(KEY)
    assert validate_address(address).format == name
    crossed = other_network(name)
    for _, candidate in swaps(address, BASE58_ALPHABET):
        check(candidate, crossed, in_format=reads_as_base58(candidate))


@pytest.mark.parametrize("name", BECH32_FORMATS)
def test_no_single_bech32_character_swap_validates(name: str) -> None:
    address = ENCODERS[name].encode(KEY)
    assert validate_address(address).format == name
    separator = address.index("1")
    crossed = other_network(name)
    for index, candidate in swaps(address, BECH32_CHARSET):
        # The charset carries no "1", so a swap in the hrp or on the separator
        # leaves a string addressed to no format here; past it the hrp stands
        # and the checksum is what has to catch the change.
        check(candidate, crossed, in_format=index > separator)


def test_flipping_the_case_of_any_eip55_letter_breaks_the_checksum() -> None:
    assert validate_address(EIP55)
    letters = [index for index, c in enumerate(EIP55[2:], start=2) if c.isalpha()]
    assert letters
    for index in letters:
        character = EIP55[index]
        flipped = character.lower() if character.isupper() else character.upper()
        candidate = EIP55[:index] + flipped + EIP55[index + 1 :]
        body = candidate[2:]
        # Still mixed case, so there is a checksum to fail rather than none.
        assert body.lower() != body and body.upper() != body, candidate
        result = validate_address(candidate, network=Network.MAINNET)
        assert not result, candidate
        assert result.reason is Reason.BAD_CHECKSUM, candidate
        assert result.format == "evm"
        assert result.network is Network.ANY
