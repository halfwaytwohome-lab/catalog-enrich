"""Normalized, alias-aware family-name lookup against a JSONL catalog snapshot.

Resolution order for a query string:

1. ``exact``            - literal match on the ``family`` field
2. ``normalized``       - match on the normalized ``family`` field
3. ``alias``            - match on a normalized entry of ``aliases``
4. ``ambiguous``        - the normalized key maps to more than one family; no record is
                          returned (we never guess)
5. ``none``             - no match

Normalization: Unicode NFKC, casefold, then drop everything that is not a letter or
digit (so ``"Xtreme RAT"``, ``"xtreme-rat"`` and ``"xtremerat"`` share a key).
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

from .mapping import map_record
from .provenance import Provenance, build_provenance

PathLike = Union[str, Path]

FAMILY_FIELD = "family"
ALIASES_FIELD = "aliases"

_NON_ALNUM = re.compile(r"[\W_]+", re.UNICODE)


def normalize_name(value: Any) -> str:
    """Return the lookup key for a family or alias string ('' for non-strings)."""
    if not isinstance(value, str):
        return ""
    return _NON_ALNUM.sub("", unicodedata.normalize("NFKC", value).casefold())


@dataclass
class LookupResult:
    query: Any
    match_method: str
    record: dict[str, Any] | None
    provenance: Provenance
    candidates: list[str] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        return self.record is not None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"query": self.query, "match_method": self.match_method}
        out.update(map_record(self.record))
        out["candidates"] = list(self.candidates)
        out["provenance"] = self.provenance.as_dict()
        return out


class SnapshotError(ValueError):
    """Raised when the snapshot cannot be parsed into family records."""


def _iter_records(path: Path) -> Iterable[dict[str, Any]]:
    with open(path, encoding="utf-8-sig") as handle:
        for line_num, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except ValueError as exc:
                raise SnapshotError(f"{path}:{line_num}: invalid JSON: {exc}") from exc
            if not isinstance(item, dict):
                raise SnapshotError(f"{path}:{line_num}: expected a JSON object")
            yield item


class Catalog:
    """In-memory index over a pinned JSONL snapshot. Read-only; never writes."""

    def __init__(
        self,
        records: list[dict[str, Any]],
        provenance: Provenance,
    ) -> None:
        self.records = records
        self.provenance = provenance
        self._exact: dict[str, list[int]] = defaultdict(list)
        self._norm_family: dict[str, set[int]] = defaultdict(set)
        self._norm_alias: dict[str, set[int]] = defaultdict(set)
        for idx, rec in enumerate(records):
            fam = rec.get(FAMILY_FIELD)
            if isinstance(fam, str) and fam:
                self._exact[fam].append(idx)
                key = normalize_name(fam)
                if key:
                    self._norm_family[key].add(idx)
            aliases = rec.get(ALIASES_FIELD)
            items = aliases if isinstance(aliases, list) else [aliases]
            for alias in items:
                key = normalize_name(alias)
                if key:
                    self._norm_alias[key].add(idx)

    @classmethod
    def from_jsonl(cls, snapshot_path: PathLike, metadata_path: PathLike | None = None) -> Catalog:
        path = Path(snapshot_path)
        if not path.is_file():
            raise FileNotFoundError(f"snapshot not found: {path}")
        records = list(_iter_records(path))
        if not any(isinstance(r.get(FAMILY_FIELD), str) for r in records):
            raise SnapshotError(f"{path}: no records with a string '{FAMILY_FIELD}' field")
        prov = build_provenance(path, record_count=len(records), metadata_path=metadata_path)
        return cls(records, prov)

    def __len__(self) -> int:
        return len(self.records)

    def _families(self, ids: Iterable[int]) -> list[str]:
        return sorted({str(self.records[i].get(FAMILY_FIELD)) for i in ids})

    def _resolve(self, query: Any, method: str, ids: set[int]) -> LookupResult:
        fams = self._families(ids)
        if len(ids) == 1:
            return LookupResult(query, method, self.records[next(iter(ids))], self.provenance)
        return LookupResult(query, "ambiguous", None, self.provenance, fams)

    def lookup(self, query: Any) -> LookupResult:
        if not isinstance(query, str) or not query.strip():
            return LookupResult(query, "none", None, self.provenance)
        if query in self._exact:
            return self._resolve(query, "exact", set(self._exact[query]))
        key = normalize_name(query)
        if not key:
            return LookupResult(query, "none", None, self.provenance)
        if key in self._norm_family:
            return self._resolve(query, "normalized", self._norm_family[key])
        if key in self._norm_alias:
            return self._resolve(query, "alias", self._norm_alias[key])
        return LookupResult(query, "none", None, self.provenance)

    def alias_collisions(self) -> dict[str, list[str]]:
        """Normalized alias keys that point at more than one family."""
        return {k: self._families(v) for k, v in sorted(self._norm_alias.items()) if len(v) > 1}
