"""Index policy for handing out deposit addresses.

A watching wallet stops scanning after a run of unused addresses -- twenty of
them, by the convention BIP44 fixed. Handing out index 500 while the scanner
looks twenty past the last used index does not lose the key, since derivation
is deterministic, but it does lose the deposit: nothing following that rule
will ever look there.

The two numbers that decide the question are the next index to hand out and the
highest index known to be used. They live here beside the gap limit they have
to respect, so the decision is made once, by the package, rather than by every
caller that needs a fresh address.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .addresses import AddressEncoder, get_encoder
from .bip32 import HARDENED_OFFSET, ExtendedPublicKey
from .errors import GapLimitError, LedgerError

__all__ = ["DEFAULT_GAP_LIMIT", "AddressLedger", "DepositAddress"]

DEFAULT_GAP_LIMIT = 20


@dataclass(frozen=True)
class DepositAddress:
    """One address, with the index and path it was derived from."""

    index: int
    path: str
    address: str
    public_key: bytes


def _check_index(value: int, label: str) -> None:
    if not 0 <= value < HARDENED_OFFSET:
        raise LedgerError(f"{label} {value} is outside the non-hardened range")


class AddressLedger:
    """Hands out deposit addresses in order, never outrunning the gap limit.

    The ledger derives from one branch of an account-level extended public key,
    usually the external chain ``0``. Pass ``branch=None`` when the key given is
    already the branch, as exported by some signers.
    """

    def __init__(
        self,
        account: ExtendedPublicKey,
        encoder: AddressEncoder | str,
        *,
        branch: int | None = 0,
        gap_limit: int = DEFAULT_GAP_LIMIT,
        next_index: int = 0,
        last_used: int | None = None,
    ) -> None:
        if gap_limit < 1:
            raise LedgerError(f"gap limit must be at least 1, got {gap_limit}")
        _check_index(next_index, "next index")
        if last_used is not None:
            _check_index(last_used, "last used index")
            if last_used >= next_index:
                raise LedgerError(
                    f"last used index {last_used} is not below the next index "
                    f"{next_index}"
                )
        self._account = account
        self._encoder = get_encoder(encoder) if isinstance(encoder, str) else encoder
        self._branch = branch
        self._branch_key = account if branch is None else account.child(branch)
        self._gap_limit = gap_limit
        self._next_index = next_index
        self._last_used = last_used

    def __repr__(self) -> str:
        return (
            f"AddressLedger(format={self._encoder.name!r}, branch={self._branch!r}, "
            f"next_index={self._next_index}, last_used={self._last_used!r}, "
            f"gap_limit={self._gap_limit})"
        )

    @property
    def account(self) -> ExtendedPublicKey:
        """The key this ledger derives from."""
        return self._account

    @property
    def encoder(self) -> AddressEncoder:
        """The encoder every issued address is produced with."""
        return self._encoder

    @property
    def branch(self) -> int | None:
        """The branch index between the account and the addresses, if any."""
        return self._branch

    @property
    def gap_limit(self) -> int:
        """How many unused addresses a scanner is assumed to look ahead."""
        return self._gap_limit

    @property
    def next_index(self) -> int:
        """The index :meth:`issue` will hand out next."""
        return self._next_index

    @property
    def last_used(self) -> int | None:
        """Highest index known to have received a deposit, if any."""
        return self._last_used

    @property
    def _scan_start(self) -> int:
        return 0 if self._last_used is None else self._last_used + 1

    @property
    def outstanding(self) -> int:
        """Addresses handed out and not yet seen used."""
        return self._next_index - self._scan_start

    @property
    def frontier(self) -> int:
        """First index a scanner honouring the gap limit would never reach."""
        return self._scan_start + self._gap_limit

    @property
    def remaining(self) -> int:
        """How many more addresses may be issued before the frontier."""
        return max(self.frontier - self._next_index, 0)

    def path(self, index: int) -> str:
        """The derivation path of *index* relative to the account key."""
        return str(index) if self._branch is None else f"{self._branch}/{index}"

    def address_at(self, index: int) -> DepositAddress:
        """Derive the address at *index* without touching the bookkeeping."""
        key = self._branch_key.child(index)
        return DepositAddress(
            index=index,
            path=self.path(index),
            address=self._encoder.encode(key.public_key),
            public_key=key.public_key,
        )

    def peek(self) -> DepositAddress:
        """The address :meth:`issue` would return, without handing it out."""
        return self.address_at(self._next_index)

    def issue(self) -> DepositAddress:
        """Hand out the next address, refusing to pass the gap limit."""
        if self.remaining == 0:
            behind = (
                "the start of the branch"
                if self._last_used is None
                else f"index {self._last_used}"
            )
            raise GapLimitError(
                f"index {self._next_index} would leave {self.outstanding + 1} "
                f"unused addresses after {behind}, past the gap limit of "
                f"{self._gap_limit}; mark a deposit as used or raise the limit"
            )
        deposit = self.address_at(self._next_index)
        self._next_index += 1
        return deposit

    def mark_used(self, index: int) -> None:
        """Record a deposit at *index*, moving the window that far forward.

        An index that was never issued is accepted: a restore from another
        system, or an address a customer kept, is already out in the world and
        the cursor must not hand it out again.
        """
        _check_index(index, "used index")
        if self._last_used is None or index > self._last_used:
            self._last_used = index
        if index >= self._next_index:
            self._next_index = index + 1

    def state(self) -> dict[str, Any]:
        """A JSON-safe snapshot :meth:`restore` can continue from."""
        return {
            "account": self._account.serialize(),
            "format": self._encoder.name,
            "branch": self._branch,
            "gap_limit": self._gap_limit,
            "next_index": self._next_index,
            "last_used": self._last_used,
        }

    @classmethod
    def restore(cls, state: Mapping[str, Any]) -> "AddressLedger":
        """Rebuild a ledger from a snapshot taken by :meth:`state`."""
        missing = sorted({"account", "format"} - set(state))
        if missing:
            raise LedgerError(f"ledger state is missing {', '.join(missing)}")
        return cls(
            ExtendedPublicKey.parse(state["account"]),
            state["format"],
            branch=state.get("branch", 0),
            gap_limit=state.get("gap_limit", DEFAULT_GAP_LIMIT),
            next_index=state.get("next_index", 0),
            last_used=state.get("last_used"),
        )
