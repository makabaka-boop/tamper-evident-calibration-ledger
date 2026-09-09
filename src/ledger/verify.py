from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ledger.errors import InvalidProofError
from ledger.proofs import verify_receipt
from ledger.security import KeyConfigurationError, decode_secret


def _read_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Offline verification of a calibration ledger receipt"
    )
    parser.add_argument("receipt", type=Path, help="receipt JSON returned by GET /v1/events/{id}")
    parser.add_argument("--keyring", type=Path, required=True, help="JSON version-to-secret map")
    args = parser.parse_args()
    try:
        receipt = _read_object(args.receipt)
        raw_keys = _read_object(args.keyring)
        keys = {str(version): decode_secret(str(secret)) for version, secret in raw_keys.items()}
        result = verify_receipt(receipt, keys)
    except InvalidProofError as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "error": {
                        "code": exc.code,
                        "message": exc.message,
                        "details": exc.details,
                    },
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from exc
    except KeyConfigurationError as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "error": {"code": "UNKNOWN_KEY_VERSION", "message": str(exc), "details": {}},
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from exc
    except (OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "error": {"code": "INPUT_ERROR", "message": str(exc), "details": {}},
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from exc
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
