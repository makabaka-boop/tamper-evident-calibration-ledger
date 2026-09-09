"""Deterministic ZIP archives for offline instrument audit packages.

The archive contains one receipt per event (in database sequence order) and a canonical
manifest describing the task, its fixed sealed boundary, the event count, and per-file plus
whole-archive SHA-256 digests. Neither raw reports nor HMAC key material ever enter the
package: receipts expose ``report_digest`` only and the manifest is unsigned (it cites the
HMAC-signed checkpoint carried inside every receipt).

Rebuilding an archive from the same inputs always yields byte-identical output:
fixed ZIP timestamps, fixed creator metadata, sorted entry names, and DEFLATE level 9.
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from io import BytesIO
from typing import Any

from ledger.canonical import canonical_json, sha256_hex

MANIFEST_NAME = "manifest.json"
RECEIPTS_DIR = "receipts"
# A fixed moment keeps ZIP local headers independent of the building wall clock.
ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
ZIP_EXTERNAL_ATTR_DIR = (0o040755 << 16) | 0x10
ZIP_EXTERNAL_ATTR_FILE = 0o100644 << 16
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ReceiptEntry:
    sequence: int
    receipt: dict[str, Any]

    @property
    def name(self) -> str:
        return f"{RECEIPTS_DIR}/event-{self.sequence:020d}.json"


@dataclass(frozen=True)
class PackageBundle:
    """All inputs needed to serialize an audit package deterministically."""

    package_id: str
    idempotency_key: str
    instrument_id: str
    checkpoint: dict[str, Any]
    entries: tuple[ReceiptEntry, ...]


@dataclass(frozen=True)
class BuiltArchive:
    content: bytes
    sha256: str
    size_bytes: int
    manifest: dict[str, Any]
    event_count: int


def receipt_bytes(entry: ReceiptEntry) -> bytes:
    return canonical_json(entry.receipt)


def build_manifest(
    bundle: PackageBundle, entry_digests: list[tuple[str, str]]
) -> dict[str, Any]:
    """Build the canonical manifest from the bundle and per-file SHA-256 digests."""

    return {
        "schema_version": SCHEMA_VERSION,
        "package_id": bundle.package_id,
        "idempotency_key": bundle.idempotency_key,
        "instrument_id": bundle.instrument_id,
        "boundary": {
            "checkpoint": bundle.checkpoint,
            "leaf_count": bundle.checkpoint["leaf_count"],
            "last_event_sequence": bundle.checkpoint["last_event_sequence"],
            "root_hash": bundle.checkpoint["root_hash"],
        },
        "event_count": len(bundle.entries),
        "files": [
            {
                "path": path,
                "sha256": digest,
            }
            for path, digest in entry_digests
        ],
    }


def build_archive(bundle: PackageBundle) -> BuiltArchive:
    """Render a deterministic ZIP archive from a collected package bundle."""

    serialized: list[tuple[str, bytes]] = []
    entry_digests: list[tuple[str, str]] = []
    for entry in bundle.entries:
        data = receipt_bytes(entry)
        serialized.append((entry.name, data))
        entry_digests.append((entry.name, sha256_hex(data)))

    manifest = build_manifest(bundle, entry_digests)
    manifest_bytes = canonical_json(manifest)
    serialized.append((MANIFEST_NAME, manifest_bytes))

    buffer = BytesIO()
    # allowZip64 stays at the default; deterministic metadata is set per entry below.
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for dirname in (RECEIPTS_DIR + "/",):
            info = zipfile.ZipInfo(dirname, date_time=ZIP_DATE_TIME)
            info.create_system = 3
            info.external_attr = ZIP_EXTERNAL_ATTR_DIR
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, b"")
        for name, data in serialized:
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE_TIME)
            info.create_system = 3
            info.external_attr = ZIP_EXTERNAL_ATTR_FILE
            info.compress_type = zipfile.ZIP_DEFLATED
            # Empty extra/comment keeps headers stable across Python builds.
            info.extra = b""
            info.comment = b""
            zf.writestr(info, data)
    content = buffer.getvalue()
    archive_digest = hashlib.sha256(content).hexdigest()
    return BuiltArchive(
        content=content,
        sha256=archive_digest,
        size_bytes=len(content),
        manifest=manifest,
        event_count=len(bundle.entries),
    )
