"""Field mapping from raw catalog records to a stable enrichment output.

Source schema (malware_families.jsonl, metadata schema_version 1.1.0) fields used:
``family``, ``aliases``, ``category``, ``enrichment_level``, ``sample_count``,
``mitre_attack``, ``mitre_attack_detail``, ``threat_actors``, ``motivation``,
``containment_steps``, ``what_to_avoid``, ``references``, ``sources``,
``cisa_advisory``, ``mitre_url``, ``last_updated``.

Deliberately NOT mapped: ``description``/``faq`` prose, and the vendor ``cta`` /
``support_cta`` marketing strings. Raw category values are never rewritten; the
normalized category is a separate, local-policy column.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MAPPING_VERSION = "v0.1.0"

GLOSSARY = (
    "trojan banker ransomware worm spyware adware backdoor rat downloader dropper rootkit "
    "miner infostealer pua virus keylogger bot exploit unknown"
).split()

# Local policy, carried over from the Phase 0 inspection. Composite or semantically
# broader categories (e.g. "worm_banker", "loader") are deliberately left unmapped.
CATEGORY_MAP: dict[str, str] = {k: k for k in GLOSSARY}
CATEGORY_MAP.update(
    {
        "banking_trojan": "banker",
        "cryptominer": "miner",
        "file_infector": "virus",
        "pup": "pua",
        "pua_tool": "pua",
        "spam_bot": "bot",
        "ddos_bot": "bot",
        "botnet": "bot",
    }
)

_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"\)]+", re.I)

# Output field order. Keep stable: it is part of the CSV contract.
OUTPUT_FIELDS: list[str] = [
    "matched_family",
    "category_raw",
    "category_normalized",
    "category_mapping_status",
    "enrichment_level",
    "sample_count",
    "aliases",
    "mitre_attack",
    "threat_actors",
    "motivation",
    "containment_step_count",
    "has_reference_url",
    "last_updated",
]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v)]
    return []


def _technique_ids(record: Mapping[str, Any]) -> list[str]:
    ids: list[str] = []
    for item in _as_list(record.get("mitre_attack")):
        if isinstance(item, str) and item.strip():
            ids.append(item.strip())
    for item in _as_list(record.get("mitre_attack_detail")):
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"].strip():
            ids.append(item["id"].strip())
    # stable de-duplication
    return list(dict.fromkeys(ids))


def normalize_category(raw: Any) -> str | None:
    return CATEGORY_MAP.get(raw) if isinstance(raw, str) else None


def map_record(record: Mapping[str, Any] | None) -> dict[str, Any]:
    """Map one raw catalog record to the enrichment output fields.

    ``None`` (no match) yields every field present with an empty value.
    """
    if record is None:
        return {
            "matched_family": None,
            "category_raw": None,
            "category_normalized": None,
            "category_mapping_status": None,
            "enrichment_level": None,
            "sample_count": None,
            "aliases": [],
            "mitre_attack": [],
            "threat_actors": [],
            "motivation": None,
            "containment_step_count": 0,
            "has_reference_url": False,
            "last_updated": None,
        }
    raw_cat = record.get("category")
    normalized = normalize_category(raw_cat)
    ref_strings = (
        _strings(record.get("references"))
        + _strings(record.get("sources"))
        + _strings(record.get("cisa_advisory"))
        + _strings(record.get("mitre_url"))
    )
    sample_count = record.get("sample_count")
    motivation = record.get("motivation")
    return {
        "matched_family": record.get("family"),
        "category_raw": raw_cat,
        "category_normalized": normalized,
        "category_mapping_status": "mapped" if normalized is not None else "unmapped",
        "enrichment_level": record.get("enrichment_level"),
        "sample_count": sample_count if isinstance(sample_count, int) else None,
        "aliases": [a for a in _as_list(record.get("aliases")) if isinstance(a, str)],
        "mitre_attack": _technique_ids(record),
        "threat_actors": [t for t in _as_list(record.get("threat_actors")) if isinstance(t, str)],
        "motivation": motivation if isinstance(motivation, str) else None,
        "containment_step_count": len(
            [s for s in _as_list(record.get("containment_steps")) if isinstance(s, str)]
        ),
        "has_reference_url": any(_URL.search(s) for s in ref_strings),
        "last_updated": record.get("last_updated"),
    }
