from __future__ import annotations

import json
from functools import lru_cache

from pydantic import PositiveFloat, PositiveInt
from pydantic_settings import BaseSettings, SettingsConfigDict

from ledger.security import KeyConfigurationError, decode_secret


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LEDGER_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    database_url: str = "postgresql+asyncpg://ledger:ledger@db:5432/ledger"
    hmac_keys_json: str | None = None
    current_key_version: str = "v1"
    seal_batch_size: PositiveInt = 100
    seal_poll_seconds: PositiveFloat = 2.0
    log_level: str = "INFO"

    @property
    def keyring(self) -> dict[str, bytes]:
        if not self.hmac_keys_json:
            raise KeyConfigurationError("LEDGER_HMAC_KEYS_JSON is required")
        try:
            raw = json.loads(self.hmac_keys_json)
        except json.JSONDecodeError as exc:
            raise KeyConfigurationError("LEDGER_HMAC_KEYS_JSON must be valid JSON") from exc
        if not isinstance(raw, dict) or not raw:
            raise KeyConfigurationError("LEDGER_HMAC_KEYS_JSON must be a non-empty object")
        decoded = {
            str(version): decode_secret(value)
            for version, value in raw.items()
            if isinstance(value, str)
        }
        if len(decoded) != len(raw):
            raise KeyConfigurationError("every HMAC key value must be a string")
        if self.current_key_version not in decoded:
            raise KeyConfigurationError("LEDGER_CURRENT_KEY_VERSION is not present in keyring")
        return decoded


@lru_cache
def get_settings() -> Settings:
    return Settings()
