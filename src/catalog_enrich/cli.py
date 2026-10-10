"""Command-line interface: ``catalog-enrich lookup`` and ``catalog-enrich enrich``."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Sequence

from . import __version__
from .lookup import Catalog
from .mapping import OUTPUT_FIELDS

PREFIX = "ce_"
PROVENANCE_COLUMNS = ["snapshot_sha256", "metadata_schema_version", "mapping_version"]


def _cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ";".join(str(v) for v in value)
    return str(value)


def _add_snapshot_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--snapshot", required=True, help="path to the pinned JSONL catalog snapshot")
    p.add_argument(
        "--metadata",
        default=None,
        help="path to metadata.json (default: metadata.json next to the snapshot)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="catalog-enrich",
        description="Offline, provenance-stamped malware family lookup (reference-only catalog).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    lk = sub.add_parser("lookup", help="look up one or more family names; prints JSON")
    _add_snapshot_args(lk)
    lk.add_argument("names", nargs="+", help="family names or aliases to look up")

    en = sub.add_parser("enrich", help="append catalog columns to a CSV with a family column")
    _add_snapshot_args(en)
    en.add_argument("input", help="input CSV path ('-' for stdin)")
    en.add_argument("-o", "--output", default="-", help="output CSV path (default: stdout)")
    en.add_argument("--family-column", default="family", help="column holding the family name")
    return parser


def _cmd_lookup(cat: Catalog, names: Sequence[str]) -> int:
    results = [cat.lookup(n).as_dict() for n in names]
    json.dump(results if len(results) > 1 else results[0], sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")
    return 0 if all(r["match_method"] not in ("none", "ambiguous") for r in results) else 1


def _cmd_enrich(cat: Catalog, input_path: str, output_path: str, family_column: str) -> int:
    src = sys.stdin if input_path == "-" else open(input_path, newline="", encoding="utf-8-sig")
    try:
        reader = csv.DictReader(src)
        in_fields: list[str] = list(reader.fieldnames or [])
        if family_column not in in_fields:
            sys.stderr.write(
                f"error: column '{family_column}' not found; columns: {', '.join(in_fields)}\n"
            )
            return 2
        added = [PREFIX + "match_method"] + [PREFIX + f for f in OUTPUT_FIELDS]
        added += [PREFIX + c for c in PROVENANCE_COLUMNS]
        clash = [c for c in added if c in in_fields]
        if clash:
            sys.stderr.write(f"error: input already has columns {clash}\n")
            return 2
        dst = (
            sys.stdout
            if output_path == "-"
            else open(output_path, "w", newline="", encoding="utf-8")
        )
        try:
            writer = csv.DictWriter(dst, fieldnames=in_fields + added, lineterminator="\n")
            writer.writeheader()
            prov = cat.provenance.as_dict()
            for row in reader:
                res = cat.lookup(row.get(family_column)).as_dict()
                out = dict(row)
                out[PREFIX + "match_method"] = res["match_method"]
                for f in OUTPUT_FIELDS:
                    out[PREFIX + f] = _cell(res[f])
                for c in PROVENANCE_COLUMNS:
                    out[PREFIX + c] = _cell(prov[c])
                writer.writerow(out)
        finally:
            if dst is not sys.stdout:
                dst.close()
    finally:
        if src is not sys.stdin:
            src.close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cat = Catalog.from_jsonl(args.snapshot, args.metadata)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    if args.command == "lookup":
        return _cmd_lookup(cat, args.names)
    return _cmd_enrich(cat, args.input, args.output, args.family_column)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
