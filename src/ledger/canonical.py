from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalizationError(ValueError):
    """The value cannot be represented by the ledger's canonical JSON profile."""


def canonical_json(value: Any) -> bytes:
    """Return stable UTF-8 JSON (sorted keys, no insignificant whitespace).

    Incoming JSON is parsed before this function is called, so alternate whitespace and
    Unicode escape spellings converge. Non-finite floating point values are rejected.
    """

    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_json(value: Any) -> str:
    return sha256_hex(canonical_json(value))
