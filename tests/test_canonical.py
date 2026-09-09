from __future__ import annotations

import math

import pytest

from ledger.canonical import CanonicalizationError, canonical_json, digest_json


def test_object_order_and_input_whitespace_converge() -> None:
    left = {"reading": 1.25, "units": "°C", "nested": {"b": True, "a": None}}
    right = {"nested": {"a": None, "b": True}, "units": "°C", "reading": 1.25}
    assert canonical_json(left) == canonical_json(right)
    assert digest_json(left) == digest_json(right)
    assert canonical_json(left) == (
        b'{"nested":{"a":null,"b":true},"reading":1.25,"units":"\xc2\xb0C"}'
    )


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_are_rejected(value: float) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json({"reading": value})


def test_one_byte_report_change_changes_digest() -> None:
    assert digest_json({"result": "accepted"}) != digest_json({"result": "acceptfd"})
