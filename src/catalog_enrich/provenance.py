"""Provenance receipt attached to every lookup / enrichment result."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Union

PathLike = Union[str, Path]

_CHUNK = 1 << 20


def sha256_file(path: PathLike) -> str:
    """Return the hex SHA-256 of a file, streamed in 1 MiB chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_metadata(path: PathLike | None) -> dict[str, Any]:
    """Load a metadata.json sidecar. Missing or unreadable metadata yields ``{}``."""
    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


@dataclass(frozen=True)
class Provenance:
    """Immutable description of the snapshot a result was derived from."""

    snapshot_path: str
    snapshot_sha256: str
    snapshot_bytes: int
    record_count: int
    metadata_path: str | None
    metadata_schema_version: str | None
    mapping_version: str
    tool_version: str
    status: str = "reference-only"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_metadata_path(snapshot_path: PathLike) -> Path:
    """``metadata.json`` next to the snapshot, the layout used by the pinned catalog."""
    return Path(snapshot_path).with_name("metadata.json")


def build_provenance(
    snapshot_path: PathLike,
    record_count: int,
    metadata_path: PathLike | None = None,
    sha256: str | None = None,
) -> Provenance:
    from . import __version__
    from .mapping import MAPPING_VERSION

    snap = Path(snapshot_path)
    meta_path = Path(metadata_path) if metadata_path else default_metadata_path(snap)
    metadata = load_metadata(meta_path)
    schema_version = metadata.get("schema_version")
    return Provenance(
        snapshot_path=str(snap),
        snapshot_sha256=sha256 or sha256_file(snap),
        snapshot_bytes=snap.stat().st_size,
        record_count=record_count,
        metadata_path=str(meta_path) if meta_path.is_file() else None,
        metadata_schema_version=str(schema_version) if schema_version is not None else None,
        mapping_version=MAPPING_VERSION,
        tool_version=__version__,
    )
