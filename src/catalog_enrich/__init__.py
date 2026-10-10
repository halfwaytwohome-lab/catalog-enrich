"""catalog-enrich: offline malware family lookup against a pinned JSONL catalog snapshot.

The catalog is treated as reference-only context. Every result carries provenance
(snapshot path, SHA-256, metadata schema version, mapping version) so downstream
consumers can tell exactly which bytes an answer came from.
"""

from .lookup import Catalog, LookupResult, normalize_name
from .mapping import CATEGORY_MAP, MAPPING_VERSION, map_record
from .provenance import Provenance, build_provenance

__version__ = "0.1.0"

__all__ = [
    "CATEGORY_MAP",
    "MAPPING_VERSION",
    "Catalog",
    "LookupResult",
    "Provenance",
    "__version__",
    "build_provenance",
    "map_record",
    "normalize_name",
]
