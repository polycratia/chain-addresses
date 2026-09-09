"""Keccak-256, checked against SHA-3 where only the padding differs."""

from __future__ import annotations

import hashlib

import pytest

from chain_addresses.keccak import _sponge, keccak256

VECTORS = [
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
]


@pytest.mark.parametrize(("data", "digest"), VECTORS)
def test_known_vectors(data: bytes, digest: str) -> None:
    assert keccak256(data).hex() == digest


@pytest.mark.parametrize(
    "length", [*range(0, 20), 67, 134, 135, 136, 137, 200, 271, 272, 273]
)
def test_the_sha3_domain_reproduces_hashlib(length: int) -> None:
    # Same permutation and rate as SHA3-256, so this pins the sponge and its padding.
    data = bytes((index * 5 + length) % 256 for index in range(length))
    assert _sponge(data, 0x06) == hashlib.sha3_256(data).digest()


def test_keccak_is_not_sha3() -> None:
    assert keccak256(b"abc") != hashlib.sha3_256(b"abc").digest()
