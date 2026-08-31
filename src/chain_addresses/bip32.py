"""BIP32 public derivation from an account-level extended key."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace

from .base58 import b58check_decode, b58check_encode
from .errors import DerivationError, ExtendedKeyError
from .ripemd160 import ripemd160
from .secp256k1 import CURVE_ORDER, compress, decompress, point_add, point_from_scalar

__all__ = [
    "HARDENED_OFFSET",
    "PUBLIC_VERSIONS",
    "ExtendedPublicKey",
    "hash160",
    "parse_path",
]

HARDENED_OFFSET = 0x80000000

_SERIALIZED_LENGTH = 78
_DECIMAL_DIGITS = frozenset("0123456789")

PUBLIC_VERSIONS: dict[int, str] = {
    0x0488B21E: "xpub",
    0x043587CF: "tpub",
    0x049D7CB2: "ypub",
    0x044A5262: "upub",
    0x04B24746: "zpub",
    0x045F1CF6: "vpub",
}

_PRIVATE_VERSIONS: dict[int, str] = {
    0x0488ADE4: "xprv",
    0x04358394: "tprv",
    0x049D7878: "yprv",
    0x044A4E28: "uprv",
    0x04B2430C: "zprv",
    0x045F18BC: "vprv",
}


def hash160(data: bytes) -> bytes:
    """Return RIPEMD160(SHA256(data)), the hash behind BIP32 fingerprints."""
    return ripemd160(hashlib.sha256(data).digest())


def parse_path(path: str) -> tuple[int, ...]:
    """Parse a relative derivation path such as ``"0/17"`` or ``"m/0/17"``.

    Hardened elements are rejected: they are unreachable without the private
    key, which is the point of handing out an account-level public key.
    """
    text = path.strip()
    if text in ("", "m", "M", "."):
        return ()
    if text[:2] in ("m/", "M/", "./"):
        text = text[2:]
    indexes = []
    for element in text.split("/"):
        if not element:
            raise DerivationError(f"empty element in path {path!r}")
        if element[-1] in ("'", "h", "H"):
            raise DerivationError(
                f"hardened element {element!r} cannot be derived from a public key"
            )
        if not set(element) <= _DECIMAL_DIGITS:
            raise DerivationError(f"invalid path element {element!r}")
        index = int(element)
        if index >= HARDENED_OFFSET:
            raise DerivationError(f"path element {element!r} is out of range")
        indexes.append(index)
    return tuple(indexes)


@dataclass(frozen=True)
class ExtendedPublicKey:
    """An extended public key: a curve point plus the chain code beside it.

    Instances hold no secret material, so a service can keep one online and
    hand out deposit addresses while the seed stays on an offline signer.
    """

    version: int
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chain_code: bytes
    public_key: bytes

    def __post_init__(self) -> None:
        if self.version not in PUBLIC_VERSIONS:
            raise ExtendedKeyError(f"unknown public key version {self.version:#010x}")
        if not 0 <= self.depth <= 255:
            raise ExtendedKeyError("depth must fit in one byte")
        if len(self.parent_fingerprint) != 4:
            raise ExtendedKeyError("parent fingerprint must be 4 bytes")
        if not 0 <= self.child_number < 2**32:
            raise ExtendedKeyError("child number must fit in four bytes")
        if len(self.chain_code) != 32:
            raise ExtendedKeyError("chain code must be 32 bytes")
        if len(self.public_key) != 33 or self.public_key[0] not in (2, 3):
            raise ExtendedKeyError("public key must be 33 compressed bytes")
        if self.depth == 0 and (
            self.parent_fingerprint != b"\x00\x00\x00\x00" or self.child_number != 0
        ):
            raise ExtendedKeyError("a master key must have no parent and no index")

    @classmethod
    def parse(cls, text: str) -> "ExtendedPublicKey":
        """Parse a serialised extended public key such as an ``xpub``."""
        payload = b58check_decode(text.strip())
        if len(payload) != _SERIALIZED_LENGTH:
            raise ExtendedKeyError(
                f"extended key must be {_SERIALIZED_LENGTH} bytes, got {len(payload)}"
            )
        version = int.from_bytes(payload[:4], "big")
        if version in _PRIVATE_VERSIONS:
            raise ExtendedKeyError(
                f"{_PRIVATE_VERSIONS[version]} is a private key; this package "
                "derives from public keys only"
            )
        if version not in PUBLIC_VERSIONS:
            raise ExtendedKeyError(f"unknown extended key version {version:#010x}")
        public_key = payload[45:]
        if public_key[0] not in (2, 3):
            raise ExtendedKeyError("extended key does not carry a compressed point")
        try:
            decompress(public_key)
        except ValueError as error:
            raise ExtendedKeyError(str(error)) from error
        return cls(
            version=version,
            depth=payload[4],
            parent_fingerprint=payload[5:9],
            child_number=int.from_bytes(payload[9:13], "big"),
            chain_code=payload[13:45],
            public_key=public_key,
        )

    def serialize(self) -> str:
        """Return the Base58Check serialisation of this key."""
        payload = (
            self.version.to_bytes(4, "big")
            + bytes([self.depth])
            + self.parent_fingerprint
            + self.child_number.to_bytes(4, "big")
            + self.chain_code
            + self.public_key
        )
        return b58check_encode(payload)

    def __str__(self) -> str:
        return self.serialize()

    @property
    def prefix(self) -> str:
        """Human-readable version prefix, for example ``"xpub"``."""
        return PUBLIC_VERSIONS[self.version]

    @property
    def identifier(self) -> bytes:
        """HASH160 of the compressed point."""
        return hash160(self.public_key)

    @property
    def fingerprint(self) -> bytes:
        """First four bytes of the identifier."""
        return self.identifier[:4]

    @property
    def point(self) -> tuple[int, int]:
        """The affine secp256k1 point behind the compressed key."""
        return decompress(self.public_key)

    def child(self, index: int) -> "ExtendedPublicKey":
        """Derive the non-hardened child at *index* (CKDpub)."""
        if not 0 <= index < HARDENED_OFFSET:
            raise DerivationError(
                f"index {index} is hardened or out of range; hardened children "
                "require the private key"
            )
        if self.depth == 255:
            raise DerivationError("cannot derive below depth 255")
        digest = hmac.new(
            self.chain_code,
            self.public_key + index.to_bytes(4, "big"),
            hashlib.sha512,
        ).digest()
        offset = int.from_bytes(digest[:32], "big")
        if not 0 < offset < CURVE_ORDER:
            raise DerivationError(f"child {index} is invalid; retry at index {index + 1}")
        child_point = point_add(point_from_scalar(offset), self.point)
        if child_point is None:
            raise DerivationError(f"child {index} is invalid; retry at index {index + 1}")
        return replace(
            self,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_number=index,
            chain_code=digest[32:],
            public_key=compress(child_point),
        )

    def derive(self, path: str) -> "ExtendedPublicKey":
        """Walk a relative path, for example ``"0/17"`` for a deposit address."""
        key = self
        for index in parse_path(path):
            key = key.child(index)
        return key
