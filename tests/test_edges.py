"""Edge cases and failure modes of the registry, validation and the ledger.

The suites beside this one check that each piece works on the inputs it was
built for. These are the awkward ones: a filter that accepts nothing, a witness
program of a length no format claims, a state file edited by hand, and the
places where one guard has to run before another for the reason a caller gets
back to be the useful one.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, dataclass, replace

import pytest

from chain_addresses import (
    CHAINS,
    DEFAULT_GAP_LIMIT,
    HARDENED_OFFSET,
    AddressLedger,
    Base58Error,
    ChainError,
    DerivationError,
    ExtendedKeyError,
    ExtendedPublicKey,
    GapLimitError,
    LedgerError,
    Network,
    Reason,
    account_path,
    chain_info,
    formats_for,
    get_encoder,
    validate_address,
)
from chain_addresses.base58 import b58check_encode
from chain_addresses.bech32 import encode as bech32_encode
from chain_addresses.secp256k1 import compress, point_from_scalar

KEY = compress(point_from_scalar(1))

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

MAINNET_P2PKH = get_encoder("bitcoin-p2pkh").encode(KEY)
TESTNET_P2PKH = get_encoder("bitcoin-testnet-p2pkh").encode(KEY)
MAINNET_P2WPKH = get_encoder("bitcoin-p2wpkh").encode(KEY)
EVM = get_encoder("evm").encode(KEY)

# A published EIP-55 vector, so the mixed case below is known canonical.
EIP55 = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

# Shaped like m/84'/0'/0': depth 3, reached by a hardened index.
ACCOUNT = ExtendedPublicKey(
    version=0x0488B21E,
    depth=3,
    parent_fingerprint=b"\x0f\x1e\x2d\x3c",
    child_number=HARDENED_OFFSET,
    chain_code=bytes(range(32)),
    public_key=KEY,
)

TPUB_VERSION = 0x043587CF
XPRV_VERSION = 0x0488ADE4


def ledger(**kwargs) -> AddressLedger:
    return AddressLedger(ACCOUNT, "bitcoin-p2wpkh", **kwargs)


# The chain registry.


@pytest.mark.parametrize("network", [Network.ANY, "any"])
def test_asking_for_any_network_lists_both(network: Network | str) -> None:
    assert formats_for("bitcoin", network) == MAINNET_FORMATS + TESTNET_FORMATS


def test_the_registry_cannot_be_edited_by_a_caller() -> None:
    with pytest.raises(TypeError):
        CHAINS["bitcoin-p2wpkh"] = chain_info("evm")


def test_a_registry_entry_cannot_be_edited_either() -> None:
    with pytest.raises(FrozenInstanceError):
        chain_info("evm").coin_type = 0


@pytest.mark.parametrize("name", ["BITCOIN-P2PKH", "bitcoin-P2WPKH", " evm", ""])
def test_format_names_are_matched_exactly(name: str) -> None:
    with pytest.raises(ChainError, match="unknown address format"):
        chain_info(name)


def test_the_unknown_format_error_lists_what_is_registered() -> None:
    with pytest.raises(ChainError) as caught:
        account_path("bitcoin-p2unknown")
    message = str(caught.value)
    assert all(name in message for name in CHAINS)


@pytest.mark.parametrize("chain", ["Bitcoin", "EVM", "", "bitcoin-p2wpkh"])
def test_chain_names_are_matched_exactly(chain: str) -> None:
    with pytest.raises(ChainError, match="unknown chain"):
        formats_for(chain)


def test_the_unknown_chain_error_lists_the_chains() -> None:
    with pytest.raises(ChainError) as caught:
        formats_for("litecoin")
    message = str(caught.value)
    assert "bitcoin" in message
    assert "evm" in message


# Validation: the filters, their order and the strings that sit between formats.


@pytest.mark.parametrize("network", [Network.ANY, "any"])
@pytest.mark.parametrize("address", [MAINNET_P2PKH, TESTNET_P2PKH, EVM])
def test_asking_for_any_network_accepts_either_chain(
    address: str, network: Network | str
) -> None:
    assert validate_address(address, network=network)


def test_a_wrong_network_is_reported_before_a_wrong_format() -> None:
    result = validate_address(
        MAINNET_P2PKH, network="testnet", formats=["bitcoin-p2wpkh"]
    )
    assert result.reason is Reason.WRONG_NETWORK
    assert result.format == "bitcoin-p2pkh"


def test_an_empty_format_filter_accepts_nothing() -> None:
    result = validate_address(MAINNET_P2PKH, formats=[])
    assert result.reason is Reason.WRONG_FORMAT
    assert result.format == "bitcoin-p2pkh"


def test_the_format_filter_takes_any_iterable() -> None:
    assert validate_address(MAINNET_P2WPKH, formats=(n for n in ["bitcoin-p2wpkh"]))
    assert validate_address(MAINNET_P2PKH, formats={"bitcoin-p2pkh", "evm"})


def test_a_format_filter_may_name_a_format_no_encoder_produces() -> None:
    p2wsh = bech32_encode("bc", 0, bytes(32))
    assert validate_address(p2wsh, formats=["bitcoin-p2wsh"])
    rejected = validate_address(p2wsh, formats=["bitcoin-p2wpkh"])
    assert rejected.reason is Reason.WRONG_FORMAT


def test_hex_without_the_0x_prefix_is_still_an_evm_address() -> None:
    result = validate_address(EIP55[2:])
    assert result
    assert result.format == "evm"
    assert result.network is Network.ANY


def test_an_uppercase_hex_prefix_is_accepted() -> None:
    assert validate_address("0X" + EIP55[2:]).format == "evm"


@pytest.mark.parametrize("body", [EIP55[2:].lower(), EIP55[2:].upper()])
def test_hex_in_one_case_has_no_checksum_to_check(body: str) -> None:
    result = validate_address("0x" + body)
    assert result
    assert "no EIP-55 checksum" in result.detail


def test_forty_hex_digits_are_read_as_hex_before_base58() -> None:
    # Every character here is also a Base58 character; the hex route wins.
    result = validate_address("a" * 40)
    assert result
    assert result.format == "evm"


def test_a_base58_payload_of_the_wrong_length_is_malformed() -> None:
    result = validate_address(b58check_encode(b"\x00" + bytes(21)))
    assert result.reason is Reason.MALFORMED
    assert "22 bytes" in result.detail
    assert "extended key" not in result.detail


@pytest.mark.parametrize(
    ("hrp", "version", "size", "network"),
    [
        ("bc", 1, 20, Network.MAINNET),
        ("tb", 1, 40, Network.TESTNET),
        ("bc", 16, 40, Network.MAINNET),
        ("tb", 2, 20, Network.TESTNET),
    ],
)
def test_an_unclaimed_witness_program_is_unsupported(
    hrp: str, version: int, size: int, network: Network
) -> None:
    result = validate_address(bech32_encode(hrp, version, bytes(size)))
    assert result.reason is Reason.UNSUPPORTED_FORMAT
    assert result.network is network
    assert f"{size}-byte" in result.detail


@pytest.mark.parametrize(
    ("address", "network"),
    [("bc1qqqqqq", Network.MAINNET), ("tb1", Network.TESTNET)],
)
def test_a_bech32_string_too_short_to_check_keeps_its_network(
    address: str, network: Network
) -> None:
    result = validate_address(address)
    assert result.reason is Reason.MALFORMED
    assert result.network is network
    assert result.format is None


REJECTED = [
    "",
    "   ",
    "hello world",
    "0x",
    "0x" + "a" * 39,
    "bc1qqqqqq",
    "tb1",
    b58check_encode(b"\x1f" + bytes(20)),
    bech32_encode("bc", 1, bytes(20)),
]


@pytest.mark.parametrize("address", REJECTED)
def test_every_rejection_names_a_reason_and_a_detail(address: str) -> None:
    result = validate_address(address)
    assert not result
    assert result.ok is False
    assert result.reason is not None
    assert result.detail


def test_the_result_carries_the_address_it_judged() -> None:
    assert validate_address(f"  {MAINNET_P2PKH}\n").address == MAINNET_P2PKH
    assert validate_address("  oops  ").address == "oops"


def test_the_verdict_enums_are_plain_strings() -> None:
    assert Network.MAINNET == "mainnet"
    assert Reason.BAD_CHECKSUM == "bad_checksum"
    assert Network("testnet") is Network.TESTNET
    assert Reason("wrong_format") is Reason.WRONG_FORMAT


# The ledger: the frontier, the branch and a state file that was edited.


def test_the_repr_shows_the_policy_and_the_cursor() -> None:
    book = ledger(gap_limit=5)
    book.issue()
    text = repr(book)
    assert "bitcoin-p2wpkh" in text
    assert "branch=0" in text
    assert "next_index=1" in text
    assert "last_used=None" in text
    assert "gap_limit=5" in text


def test_peek_still_works_when_nothing_more_may_be_issued() -> None:
    book = ledger(gap_limit=1)
    book.issue()
    assert book.remaining == 0
    assert book.peek().index == 1
    with pytest.raises(GapLimitError):
        book.issue()
    assert book.next_index == 1
    assert book.peek().index == 1


def test_the_gap_limit_error_names_what_the_window_starts_behind() -> None:
    book = ledger(gap_limit=2)
    book.issue()
    book.issue()
    with pytest.raises(GapLimitError) as caught:
        book.issue()
    assert "the start of the branch" in str(caught.value)

    book.mark_used(1)
    book.issue()
    book.issue()
    with pytest.raises(GapLimitError) as caught:
        book.issue()
    assert "index 1" in str(caught.value)


def test_a_gap_limit_of_one_hands_out_one_address_at_a_time() -> None:
    book = ledger(gap_limit=1)
    for index in range(3):
        assert book.issue().index == index
        with pytest.raises(GapLimitError):
            book.issue()
        book.mark_used(index)
    assert book.next_index == 3


def test_a_last_used_index_just_below_the_cursor_is_accepted() -> None:
    book = ledger(next_index=5, last_used=4)
    assert book.outstanding == 0
    assert book.frontier == 5 + DEFAULT_GAP_LIMIT
    assert book.remaining == DEFAULT_GAP_LIMIT
    assert book.issue().index == 5


def test_marking_a_far_index_moves_the_whole_window_forward() -> None:
    book = ledger(gap_limit=5)
    book.issue()
    book.mark_used(100)
    assert book.next_index == 101
    assert book.frontier == 106
    assert book.remaining == 5
    assert book.issue().index == 101


def test_the_last_index_of_the_branch_is_the_end_of_the_line() -> None:
    book = ledger()
    book.mark_used(HARDENED_OFFSET - 1)
    assert book.next_index == HARDENED_OFFSET
    assert book.remaining == DEFAULT_GAP_LIMIT
    with pytest.raises(DerivationError):
        book.issue()


def test_address_at_rejects_a_negative_index() -> None:
    with pytest.raises(DerivationError):
        ledger().address_at(-1)


def test_a_change_branch_derives_its_own_addresses() -> None:
    internal = AddressLedger(ACCOUNT, "bitcoin-p2wpkh", branch=1)
    deposit = internal.issue()
    assert deposit.path == "1/0"
    assert deposit.address == get_encoder("bitcoin-p2wpkh").encode(
        ACCOUNT.derive("1/0").public_key
    )
    assert deposit.address != ledger().address_at(0).address


@pytest.mark.parametrize("branch", [-1, HARDENED_OFFSET])
def test_a_branch_outside_the_public_range_cannot_be_walked(branch: int) -> None:
    with pytest.raises(DerivationError):
        AddressLedger(ACCOUNT, "bitcoin-p2wpkh", branch=branch)


@dataclass(frozen=True)
class HexEncoder:
    """An encoder of no registered chain, so it claims no network."""

    name: str = "hex"

    def encode(self, public_key: bytes) -> str:
        return public_key.hex()


def test_an_encoder_outside_the_registry_carries_no_network_claim() -> None:
    book = AddressLedger(ACCOUNT, HexEncoder())
    assert book.issue().address == ACCOUNT.derive("0/0").public_key.hex()
    testnet = AddressLedger(replace(ACCOUNT, version=TPUB_VERSION), HexEncoder())
    assert testnet.issue().index == 0


def test_a_branch_key_state_round_trips_with_a_null_branch() -> None:
    book = AddressLedger(ACCOUNT.child(0), "bitcoin-p2wpkh", branch=None)
    book.issue()
    state = book.state()
    assert state["branch"] is None
    assert json.loads(json.dumps(state)) == state
    restored = AddressLedger.restore(state)
    assert restored.branch is None
    assert restored.peek() == book.peek()


def test_the_state_is_the_key_the_policy_and_the_two_cursors() -> None:
    state = ledger(gap_limit=7, next_index=3, last_used=1).state()
    assert sorted(state) == [
        "account",
        "branch",
        "format",
        "gap_limit",
        "last_used",
        "next_index",
    ]
    assert state["account"] == ACCOUNT.serialize()
    assert state["format"] == "bitcoin-p2wpkh"


def test_restore_ignores_a_key_it_does_not_know() -> None:
    state = {**ledger().state(), "note": "written by another tool"}
    assert AddressLedger.restore(state).next_index == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"gap_limit": 0},
        {"next_index": -1},
        {"next_index": HARDENED_OFFSET},
        {"last_used": 5, "next_index": 2},
    ],
)
def test_restore_validates_the_policy_it_is_handed(overrides: dict) -> None:
    with pytest.raises(LedgerError):
        AddressLedger.restore({**ledger().state(), **overrides})


def test_restore_rejects_an_account_that_fails_its_checksum() -> None:
    state = ledger().state()
    text = state["account"]
    state["account"] = text[:-1] + ("2" if text[-1] != "2" else "3")
    with pytest.raises(Base58Error, match="checksum"):
        AddressLedger.restore(state)


def test_restore_rejects_a_private_key_in_the_state() -> None:
    payload = (
        XPRV_VERSION.to_bytes(4, "big")
        + bytes([3])
        + b"\x0f\x1e\x2d\x3c"
        + HARDENED_OFFSET.to_bytes(4, "big")
        + bytes(range(32))
        + b"\x00"
        + bytes(31)
        + b"\x01"
    )
    state = ledger().state()
    state["account"] = b58check_encode(payload)
    with pytest.raises(ExtendedKeyError, match="xprv"):
        AddressLedger.restore(state)


def test_restoring_an_empty_state_names_every_missing_key() -> None:
    with pytest.raises(LedgerError) as caught:
        AddressLedger.restore({})
    assert "account, format" in str(caught.value)


def test_restoring_a_state_without_a_format_names_it() -> None:
    with pytest.raises(LedgerError, match="format"):
        AddressLedger.restore({"account": ACCOUNT.serialize()})
