from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Mapping


class KeyConfigurationError(ValueError):
    """Versioned HMAC key material is absent, malformed, or too short."""


def decode_secret(value: str) -> bytes:
    if value.startswith("base64:"):
        try:
            secret = base64.b64decode(value.removeprefix("base64:"), validate=True)
        except ValueError as exc:
            raise KeyConfigurationError("invalid base64 HMAC key") from exc
    else:
        secret = value.encode("utf-8")
    if len(secret) < 32:
        raise KeyConfigurationError("HMAC keys must contain at least 32 bytes")
    return secret


def sign_checkpoint(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_checkpoint_signature(payload: bytes, signature: str, key: bytes) -> bool:
    expected = sign_checkpoint(payload, key)
    return hmac.compare_digest(expected, signature)


def require_key(keyring: Mapping[str, bytes], version: str) -> bytes:
    try:
        return keyring[version]
    except KeyError as exc:
        raise KeyConfigurationError(f"unknown HMAC key version: {version}") from exc
