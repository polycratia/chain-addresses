"""The little of secp256k1 that public-only derivation needs.

Only point addition and scalar multiplication of the generator are required:
CKDpub adds ``IL * G`` to the parent point. No private key ever reaches this
module.
"""

from __future__ import annotations

__all__ = [
    "CURVE_ORDER",
    "FIELD_PRIME",
    "Point",
    "compress",
    "decompress",
    "point_add",
    "point_from_scalar",
]

Point = tuple[int, int]

FIELD_PRIME = 2**256 - 2**32 - 977
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_GENERATOR: Point = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

_Jacobian = tuple[int, int, int]
_INFINITY: _Jacobian = (0, 0, 0)


def _double(point: _Jacobian) -> _Jacobian:
    x, y, z = point
    if y == 0 or z == 0:
        return _INFINITY
    y_squared = y * y % FIELD_PRIME
    s = 4 * x * y_squared % FIELD_PRIME
    m = 3 * x * x % FIELD_PRIME
    new_x = (m * m - 2 * s) % FIELD_PRIME
    new_y = (m * (s - new_x) - 8 * y_squared * y_squared) % FIELD_PRIME
    new_z = 2 * y * z % FIELD_PRIME
    return (new_x, new_y, new_z)


def _add(left: _Jacobian, right: _Jacobian) -> _Jacobian:
    if left[2] == 0:
        return right
    if right[2] == 0:
        return left
    x1, y1, z1 = left
    x2, y2, z2 = right
    z1_squared = z1 * z1 % FIELD_PRIME
    z2_squared = z2 * z2 % FIELD_PRIME
    u1 = x1 * z2_squared % FIELD_PRIME
    u2 = x2 * z1_squared % FIELD_PRIME
    s1 = y1 * z2_squared % FIELD_PRIME * z2 % FIELD_PRIME
    s2 = y2 * z1_squared % FIELD_PRIME * z1 % FIELD_PRIME
    if u1 == u2:
        if s1 != s2:
            return _INFINITY
        return _double(left)
    h = (u2 - u1) % FIELD_PRIME
    r = (s2 - s1) % FIELD_PRIME
    h_squared = h * h % FIELD_PRIME
    h_cubed = h * h_squared % FIELD_PRIME
    u1_h_squared = u1 * h_squared % FIELD_PRIME
    new_x = (r * r - h_cubed - 2 * u1_h_squared) % FIELD_PRIME
    new_y = (r * (u1_h_squared - new_x) - s1 * h_cubed) % FIELD_PRIME
    new_z = h * z1 % FIELD_PRIME * z2 % FIELD_PRIME
    return (new_x, new_y, new_z)


def _multiply(point: _Jacobian, scalar: int) -> _Jacobian:
    result = _INFINITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _double(addend)
        scalar >>= 1
    return result


def _to_affine(point: _Jacobian) -> Point | None:
    x, y, z = point
    if z == 0:
        return None
    z_inverse = pow(z, FIELD_PRIME - 2, FIELD_PRIME)
    z_inverse_squared = z_inverse * z_inverse % FIELD_PRIME
    return (
        x * z_inverse_squared % FIELD_PRIME,
        y * z_inverse_squared % FIELD_PRIME * z_inverse % FIELD_PRIME,
    )


def point_from_scalar(scalar: int) -> Point:
    """Return ``scalar * G``. The scalar must be a valid non-zero curve scalar."""
    if not 0 < scalar < CURVE_ORDER:
        raise ValueError("scalar is outside the range [1, curve order)")
    affine = _to_affine(_multiply((*_GENERATOR, 1), scalar))
    if affine is None:  # pragma: no cover - unreachable for a valid scalar
        raise ValueError("scalar multiplication produced the point at infinity")
    return affine


def point_add(left: Point, right: Point) -> Point | None:
    """Add two curve points, returning ``None`` for the point at infinity."""
    return _to_affine(_add((*left, 1), (*right, 1)))


def compress(point: Point) -> bytes:
    """Serialise *point* in the 33-byte compressed SEC form."""
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def decompress(data: bytes) -> Point:
    """Recover a curve point from its 33-byte compressed SEC form."""
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("compressed point must be 33 bytes starting with 0x02 or 0x03")
    x = int.from_bytes(data[1:], "big")
    if x >= FIELD_PRIME:
        raise ValueError("point x coordinate is outside the field")
    y_squared = (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    y = pow(y_squared, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
    if y * y % FIELD_PRIME != y_squared:
        raise ValueError("point is not on secp256k1")
    if y & 1 != data[0] & 1:
        y = FIELD_PRIME - y
    return (x, y)
