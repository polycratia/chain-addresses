"""RIPEMD-160, including the fallback used where OpenSSL no longer offers it."""

from __future__ import annotations

import hashlib

import pytest

from chain_addresses.ripemd160 import (
    _HASHLIB_SUPPORTS_RIPEMD160,
    _pure_ripemd160,
    ripemd160,
)

VECTORS = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
]


@pytest.mark.parametrize(("data", "digest"), VECTORS)
def test_known_vectors(data: bytes, digest: str) -> None:
    assert ripemd160(data).hex() == digest


@pytest.mark.parametrize(("data", "digest"), VECTORS)
def test_fallback_known_vectors(data: bytes, digest: str) -> None:
    assert _pure_ripemd160(data).hex() == digest


@pytest.mark.skipif(
    not _HASHLIB_SUPPORTS_RIPEMD160, reason="this build of OpenSSL has no ripemd160"
)
def test_fallback_matches_hashlib_across_block_boundaries() -> None:
    for length in range(0, 200):
        data = bytes((index * 7 + length) % 256 for index in range(length))
        assert _pure_ripemd160(data) == hashlib.new("ripemd160", data).digest()
