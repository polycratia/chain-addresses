"""Keccak-256, the hash behind EVM addresses.

Ethereum froze Keccak before it became SHA-3, so ``hashlib.sha3_256`` is not a
substitute: the two share the permutation and differ only in the domain
separator appended during padding.
"""

from __future__ import annotations

__all__ = ["keccak256"]

_MASK = (1 << 64) - 1
_RATE = 136
_DIGEST_LANES = 4

_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def _rotate(value: int, count: int) -> int:
    return ((value << count) | (value >> (64 - count))) & _MASK


def _permute(state: list[int]) -> None:
    for round_constant in _ROUND_CONSTANTS:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        for x in range(5):
            parity = columns[(x - 1) % 5] ^ _rotate(columns[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                state[x + y] ^= parity
        scrambled = [0] * 25
        for x in range(5):
            for y in range(5):
                scrambled[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate(
                    state[x + 5 * y], _ROTATIONS[x][y]
                )
        for y in range(0, 25, 5):
            row = scrambled[y : y + 5]
            for x in range(5):
                state[x + y] = row[x] ^ ((row[(x + 1) % 5] ^ _MASK) & row[(x + 2) % 5])
        state[0] ^= round_constant


def _sponge(data: bytes, domain: int) -> bytes:
    padded = bytearray(data)
    padded.append(domain)
    while len(padded) % _RATE:
        padded.append(0)
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), _RATE):
        for lane in range(_RATE // 8):
            start = offset + 8 * lane
            state[lane] ^= int.from_bytes(padded[start : start + 8], "little")
        _permute(state)
    return b"".join(state[lane].to_bytes(8, "little") for lane in range(_DIGEST_LANES))


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of *data*."""
    return _sponge(data, 0x01)
