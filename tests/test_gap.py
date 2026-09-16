"""The ledger must refuse to hand out an address a scanner would never reach."""

from __future__ import annotations

import json

import pytest

from chain_addresses import (
    DEFAULT_GAP_LIMIT,
    HARDENED_OFFSET,
    AddressError,
    AddressLedger,
    DerivationError,
    ExtendedPublicKey,
    GapLimitError,
    LedgerError,
    get_encoder,
)
from chain_addresses.secp256k1 import compress, point_from_scalar

ACCOUNT = ExtendedPublicKey(
    version=0x0488B21E,
    depth=0,
    parent_fingerprint=b"\x00\x00\x00\x00",
    child_number=0,
    chain_code=bytes(range(32)),
    public_key=compress(point_from_scalar(1)),
)


def ledger(**kwargs) -> AddressLedger:
    return AddressLedger(ACCOUNT, "bitcoin-p2wpkh", **kwargs)


def test_an_issued_address_matches_direct_derivation() -> None:
    deposit = ledger().issue()
    expected = get_encoder("bitcoin-p2wpkh").encode(ACCOUNT.derive("0/0").public_key)
    assert deposit.index == 0
    assert deposit.path == "0/0"
    assert deposit.address == expected
    assert deposit.public_key == ACCOUNT.derive("0/0").public_key


def test_addresses_are_handed_out_in_order_and_never_repeat() -> None:
    book = ledger()
    issued = [book.issue() for _ in range(4)]
    assert [deposit.index for deposit in issued] == [0, 1, 2, 3]
    assert len({deposit.address for deposit in issued}) == 4
    assert book.next_index == 4
    assert book.last_used is None


def test_issuing_stops_at_the_gap_limit() -> None:
    book = ledger(gap_limit=5)
    for expected in range(5):
        assert book.issue().index == expected
    assert book.remaining == 0
    assert book.outstanding == 5
    with pytest.raises(GapLimitError, match="gap limit"):
        book.issue()


def test_the_default_gap_limit_is_the_bip44_convention() -> None:
    assert DEFAULT_GAP_LIMIT == 20
    assert ledger().gap_limit == 20


def test_a_used_address_frees_exactly_the_room_ahead_of_it() -> None:
    book = ledger(gap_limit=5)
    for _ in range(5):
        book.issue()
    book.mark_used(0)
    assert book.remaining == 1
    assert book.issue().index == 5
    with pytest.raises(GapLimitError):
        book.issue()


def test_marking_the_newest_address_reopens_the_whole_window() -> None:
    book = ledger(gap_limit=5)
    for _ in range(5):
        book.issue()
    book.mark_used(4)
    assert book.outstanding == 0
    assert book.remaining == 5


def test_marking_an_older_index_does_not_move_the_window_back() -> None:
    book = ledger(gap_limit=5)
    for _ in range(3):
        book.issue()
    book.mark_used(2)
    book.mark_used(0)
    assert book.last_used == 2
    assert book.next_index == 3


def test_marking_an_index_that_was_never_issued_moves_the_cursor_past_it() -> None:
    book = ledger()
    book.mark_used(7)
    assert book.last_used == 7
    assert book.next_index == 8
    assert book.issue().index == 8


def test_the_frontier_is_the_first_index_a_scanner_would_miss() -> None:
    book = ledger(gap_limit=20)
    assert book.frontier == 20
    book.mark_used(3)
    assert book.frontier == 24
    assert book.remaining == 20


def test_a_lowered_gap_limit_never_reports_negative_room() -> None:
    book = ledger(gap_limit=2, next_index=10, last_used=0)
    assert book.outstanding == 9
    assert book.remaining == 0
    with pytest.raises(GapLimitError):
        book.issue()


def test_peeking_does_not_hand_the_address_out() -> None:
    book = ledger()
    peeked = book.peek()
    assert book.next_index == 0
    assert peeked == book.issue()
    assert book.next_index == 1


def test_address_at_derives_any_index_without_bookkeeping() -> None:
    book = ledger()
    far = book.address_at(500)
    assert far.path == "0/500"
    assert far.address == get_encoder("bitcoin-p2wpkh").encode(
        ACCOUNT.derive("0/500").public_key
    )
    assert book.next_index == 0
    assert book.remaining == DEFAULT_GAP_LIMIT


def test_address_at_rejects_a_hardened_index() -> None:
    with pytest.raises(DerivationError):
        ledger().address_at(HARDENED_OFFSET)


@pytest.mark.parametrize("index", [-1, HARDENED_OFFSET])
def test_marking_an_index_outside_the_public_range_is_rejected(index: int) -> None:
    with pytest.raises(LedgerError):
        ledger().mark_used(index)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"gap_limit": 0},
        {"gap_limit": -1},
        {"next_index": -1},
        {"next_index": HARDENED_OFFSET},
        {"last_used": -1, "next_index": 5},
        {"last_used": 5, "next_index": 5},
        {"last_used": 6, "next_index": 5},
    ],
)
def test_the_constructor_validates_its_policy(kwargs: dict) -> None:
    with pytest.raises(LedgerError):
        ledger(**kwargs)


def test_an_unknown_format_is_rejected_when_the_ledger_is_built() -> None:
    with pytest.raises(AddressError, match="unknown address format"):
        AddressLedger(ACCOUNT, "bitcoin-p2unknown")


def test_an_encoder_may_be_passed_instead_of_its_name() -> None:
    book = AddressLedger(ACCOUNT, get_encoder("evm"))
    assert book.issue().address.startswith("0x")
    assert book.encoder.name == "evm"


def test_a_branch_key_can_be_used_directly() -> None:
    book = AddressLedger(ACCOUNT.child(0), "bitcoin-p2wpkh", branch=None)
    deposit = book.issue()
    assert deposit.path == "0"
    assert deposit.address == ledger().address_at(0).address


def test_state_round_trips_through_json_and_continues_where_it_left_off() -> None:
    book = ledger(gap_limit=5)
    book.issue()
    book.issue()
    book.mark_used(1)
    state = book.state()
    assert json.loads(json.dumps(state)) == state

    restored = AddressLedger.restore(state)
    assert restored.next_index == book.next_index
    assert restored.last_used == 1
    assert restored.gap_limit == 5
    assert restored.branch == 0
    assert restored.peek() == book.peek()


def test_a_restored_ledger_keeps_the_account_it_was_built_from() -> None:
    assert AddressLedger.restore(ledger().state()).account == ACCOUNT


def test_restoring_a_state_without_an_account_is_a_ledger_error() -> None:
    with pytest.raises(LedgerError, match="account"):
        AddressLedger.restore({"format": "evm"})
