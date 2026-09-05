"""Public derivation must match private derivation and refuse private input."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace

import pytest

from chain_addresses import (
    HARDENED_OFFSET,
    Base58Error,
    DerivationError,
    ExtendedKeyError,
    ExtendedPublicKey,
    hash160,
    parse_path,
)
from chain_addresses.base58 import b58check_encode
from chain_addresses.secp256k1 import CURVE_ORDER, compress, point_from_scalar

XPUB_VERSION = 0x0488B21E
XPRV_VERSION = 0x0488ADE4
TPUB_VERSION = 0x043587CF

SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


@dataclass(frozen=True)
class ReferencePrivateKey:
    """CKDpriv, kept in the tests so CKDpub can be checked against it."""

    secret: int
    chain_code: bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    child_number: int = 0

    @property
    def public_key(self) -> bytes:
        return compress(point_from_scalar(self.secret))

    def child(self, index: int) -> "ReferencePrivateKey":
        digest = hmac.new(
            self.chain_code,
            self.public_key + index.to_bytes(4, "big"),
            hashlib.sha512,
        ).digest()
        return ReferencePrivateKey(
            secret=(int.from_bytes(digest[:32], "big") + self.secret) % CURVE_ORDER,
            chain_code=digest[32:],
            depth=self.depth + 1,
            parent_fingerprint=hash160(self.public_key)[:4],
            child_number=index,
        )

    def extended_public_key(self) -> ExtendedPublicKey:
        return ExtendedPublicKey(
            version=XPUB_VERSION,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            chain_code=self.chain_code,
            public_key=self.public_key,
        )


def master_private_key(seed: bytes = SEED) -> ReferencePrivateKey:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return ReferencePrivateKey(int.from_bytes(digest[:32], "big"), digest[32:])


MASTER = master_private_key()
MASTER_XPUB = MASTER.extended_public_key()


def serialized(
    *,
    version: int = XPUB_VERSION,
    depth: int = 0,
    parent_fingerprint: bytes = b"\x00\x00\x00\x00",
    child_number: int = 0,
    chain_code: bytes = MASTER.chain_code,
    key: bytes = MASTER.public_key,
) -> str:
    payload = (
        version.to_bytes(4, "big")
        + bytes([depth])
        + parent_fingerprint
        + child_number.to_bytes(4, "big")
        + chain_code
        + key
    )
    return b58check_encode(payload)


@pytest.mark.parametrize("index", [0, 1, 17, 1000, HARDENED_OFFSET - 1])
def test_child_matches_private_derivation(index: int) -> None:
    expected = MASTER.child(index).extended_public_key()
    assert MASTER_XPUB.child(index) == expected


def test_derive_walks_the_whole_path() -> None:
    expected = MASTER.child(0).child(17).extended_public_key()
    assert MASTER_XPUB.derive("0/17") == expected
    assert MASTER_XPUB.derive("0/17") == MASTER_XPUB.child(0).child(17)


@pytest.mark.parametrize("path", ["0/17", "m/0/17", "M/0/17", "./0/17", " 0/17 "])
def test_derive_accepts_the_usual_path_prefixes(path: str) -> None:
    assert MASTER_XPUB.derive(path) == MASTER_XPUB.child(0).child(17)


@pytest.mark.parametrize("path", ["", "m", "M", "."])
def test_empty_path_returns_the_same_key(path: str) -> None:
    assert MASTER_XPUB.derive(path) == MASTER_XPUB


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("", ()),
        ("m", ()),
        ("0", (0,)),
        ("0/17", (0, 17)),
        ("m/1/2/3", (1, 2, 3)),
        ("0/2147483647", (0, HARDENED_OFFSET - 1)),
    ],
)
def test_parse_path(path: str, expected: tuple[int, ...]) -> None:
    assert parse_path(path) == expected


@pytest.mark.parametrize(
    "path",
    ["0'/1", "0h/1", "0H/1", "0//1", "0/", "0/-1", "0/ 1", "0/x", "0/2147483648"],
)
def test_parse_path_rejects_unusable_elements(path: str) -> None:
    with pytest.raises(DerivationError):
        parse_path(path)


@pytest.mark.parametrize("index", [-1, HARDENED_OFFSET, 2**32])
def test_child_rejects_indexes_outside_the_public_range(index: int) -> None:
    with pytest.raises(DerivationError):
        MASTER_XPUB.child(index)


def test_child_refuses_to_pass_the_depth_limit() -> None:
    deep = replace(MASTER_XPUB, depth=255, child_number=1)
    with pytest.raises(DerivationError):
        deep.child(0)


def test_serialisation_round_trip() -> None:
    child = MASTER_XPUB.derive("0/17")
    assert ExtendedPublicKey.parse(child.serialize()) == child
    assert str(child) == child.serialize()
    assert child.prefix == "xpub"


def test_parse_ignores_surrounding_whitespace() -> None:
    text = MASTER_XPUB.serialize()
    assert ExtendedPublicKey.parse(f"  {text}\n") == MASTER_XPUB


def test_parse_accepts_other_public_versions() -> None:
    key = ExtendedPublicKey.parse(serialized(version=TPUB_VERSION))
    assert key.prefix == "tpub"


def test_parse_rejects_a_private_key() -> None:
    text = serialized(
        version=XPRV_VERSION, key=b"\x00" + MASTER.secret.to_bytes(32, "big")
    )
    with pytest.raises(ExtendedKeyError, match="xprv"):
        ExtendedPublicKey.parse(text)


def test_parse_rejects_an_unknown_version() -> None:
    with pytest.raises(ExtendedKeyError, match="unknown extended key version"):
        ExtendedPublicKey.parse(serialized(version=0x01020304))


def test_parse_rejects_a_broken_checksum() -> None:
    text = MASTER_XPUB.serialize()
    tampered = text[:-1] + ("2" if text[-1] != "2" else "3")
    with pytest.raises(Base58Error):
        ExtendedPublicKey.parse(tampered)


def test_parse_rejects_a_short_payload() -> None:
    with pytest.raises(ExtendedKeyError, match="78 bytes"):
        ExtendedPublicKey.parse(b58check_encode(b"\x04\x88\xb2\x1e" + b"\x00" * 40))


def test_parse_rejects_an_uncompressed_point() -> None:
    with pytest.raises(ExtendedKeyError, match="compressed point"):
        ExtendedPublicKey.parse(serialized(key=b"\x04" + b"\x11" * 32))


def test_parse_rejects_a_point_outside_the_field() -> None:
    with pytest.raises(ExtendedKeyError):
        ExtendedPublicKey.parse(serialized(key=b"\x02" + b"\xff" * 32))


def test_child_fingerprint_links_back_to_the_parent() -> None:
    child = MASTER_XPUB.child(17)
    assert child.parent_fingerprint == MASTER_XPUB.fingerprint
    assert MASTER_XPUB.fingerprint == MASTER_XPUB.identifier[:4]
    assert MASTER_XPUB.identifier == hash160(MASTER_XPUB.public_key)
    assert child.depth == 1
    assert child.child_number == 17


def test_point_matches_the_compressed_key() -> None:
    assert compress(MASTER_XPUB.point) == MASTER_XPUB.public_key


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": 0x01020304},
        {"depth": 256},
        {"depth": -1},
        {"parent_fingerprint": b"\x00\x00\x00"},
        {"depth": 1, "child_number": 2**32},
        {"chain_code": b"\x00" * 31},
        {"public_key": b"\x02" * 32},
        {"public_key": b"\x04" + b"\x11" * 32},
        {"parent_fingerprint": b"\x01\x02\x03\x04"},
        {"child_number": 1},
    ],
)
def test_constructor_validates_its_fields(overrides: dict) -> None:
    fields = {
        "version": XPUB_VERSION,
        "depth": 0,
        "parent_fingerprint": b"\x00\x00\x00\x00",
        "child_number": 0,
        "chain_code": MASTER.chain_code,
        "public_key": MASTER.public_key,
        **overrides,
    }
    with pytest.raises(ExtendedKeyError):
        ExtendedPublicKey(**fields)
