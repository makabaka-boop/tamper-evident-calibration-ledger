from __future__ import annotations

from typing import Any


class LedgerError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class NotFoundError(LedgerError):
    def __init__(self, entity: str, identifier: str) -> None:
        super().__init__(
            "NOT_FOUND", f"{entity} was not found", 404, {"entity": entity, "id": identifier}
        )


class InvalidProofError(LedgerError):
    def __init__(self, reason: str, details: dict[str, Any] | None = None) -> None:
        super().__init__("INVALID_PROOF", reason, 422, details)
