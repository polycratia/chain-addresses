"""The curve arithmetic behind CKDpub."""

from __future__ import annotations

import pytest

from chain_addresses.secp256k1 import (
    CURVE_ORDER,
    FIELD_PRIME,
    compress,
    decompress,
    point_add,
    point_from_scalar,
)


@pytest.mark.parametrize("scalar", [1, 2, 3, 7, 2**128, CURVE_ORDER - 1])
def test_generated_points_lie_on_the_curve(scalar: int) -> None:
    x, y = point_from_scalar(scalar)
    assert y * y % FIELD_PRIME == (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME


@pytest.mark.parametrize("scalar", [1, 2, 5, 2**200])
def test_compression_round_trip(scalar: int) -> None:
    point = point_from_scalar(scalar)
    data = compress(point)
    assert len(data) == 33
    assert data[0] == 2 + (point[1] & 1)
    assert decompress(data) == point


@pytest.mark.parametrize(("left", "right"), [(1, 1), (2, 3), (5, 7), (2**64, 9)])
def test_addition_agrees_with_scalar_multiplication(left: int, right: int) -> None:
    total = point_from_scalar(left + right)
    assert point_add(point_from_scalar(left), point_from_scalar(right)) == total


def test_a_point_plus_its_negation_is_infinity() -> None:
    x, y = point_from_scalar(1)
    assert point_add((x, y), (x, FIELD_PRIME - y)) is None


@pytest.mark.parametrize("scalar", [0, -1, CURVE_ORDER, CURVE_ORDER + 1])
def test_scalars_outside_the_group_are_rejected(scalar: int) -> None:
    with pytest.raises(ValueError):
        point_from_scalar(scalar)


@pytest.mark.parametrize(
    "data",
    [b"", b"\x02", b"\x02" + b"\x01" * 31, b"\x04" + b"\x01" * 32, b"\x00" * 33],
)
def test_decompress_rejects_malformed_input(data: bytes) -> None:
    with pytest.raises(ValueError):
        decompress(data)


def test_decompress_rejects_an_x_outside_the_field() -> None:
    with pytest.raises(ValueError, match="outside the field"):
        decompress(b"\x02" + b"\xff" * 32)


def test_decompress_rejects_points_off_the_curve() -> None:
    # Only about half of all x coordinates have a matching y on secp256k1.
    rejected = 0
    for x in range(1, 40):
        try:
            decompress(b"\x02" + x.to_bytes(32, "big"))
        except ValueError:
            rejected += 1
    assert rejected > 0
