# catalog-enrich

<!-- TODO(repo-url): replace OWNER/catalog-enrich below with the real GitHub path once the repo exists. -->
[![CI](https://github.com/OWNER/catalog-enrich/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/catalog-enrich/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

> **TODO (repo URL):** the badges above point at the placeholder `OWNER/catalog-enrich`.
> Replace it (here and in `pyproject.toml` `[project.urls]`) when the public repository is created.

Offline, provenance-stamped malware **family-name lookup** and **CSV enrichment** against a
pinned JSONL catalog snapshot. Zero runtime dependencies (standard library only).

**Status: v0.1.0, alpha. The catalog is reference-only context, not ground truth.**

## Why

Alert pipelines (SIEM / EDR exports) usually carry a free-text malware family string such as
`Emotet`, `geodo`, or `Xtreme RAT`. `catalog-enrich` resolves that string against a pinned
catalog snapshot and appends a small, stable set of columns (category, ATT&CK technique IDs,
enrichment level, ...) so an analyst can triage with context, while every row records exactly
which snapshot bytes produced it (SHA-256, metadata schema version, mapping version).

## Limits

Please read these before relying on the output.

- **Reference-only catalog.** The upstream catalog (about 2.9k families, built from EMBER 2018 with
  AVClass labels plus vendor-written prose) was inspected in an offline Phase 0 review and accepted
  as reference-only. Most records are not independently sourced: in the inspected snapshot only a
  small minority are `curated_sourced` / `high`; many are `expert-seo` or
  `insufficient_information`. Treat category and technique fields as hints, not verdicts.
- **The snapshot is not bundled.** This package ships no catalog data. You supply your own pinned
  `malware_families.jsonl` (and optionally its `metadata.json`). The only data in this repo is a
  tiny **synthetic** test fixture in `tests/fixtures/` (real family names, invented contents).
- **Name matching only.** Lookup works on family / alias strings. It does no hash, YARA, or
  behavioural matching and cannot tell you whether a host is actually infected.
- **No guessing.** If a normalized name maps to more than one family the result is `ambiguous`
  with no record. Fuzzy / edit-distance matching is intentionally out of scope for v0.1.0.
- **Category normalization is local policy.** `category_raw` is never rewritten.
  `category_normalized` uses a small explicit map (for example `banking_trojan` to `banker`);
  composite values such as `worm_banker` or `loader` stay `unmapped` on purpose.
- **Marketing text is dropped.** Vendor call-to-action strings (`cta`, `support_cta`) and long
  prose (`description`, `faq`) are not copied into enrichment output.
- **Not validated against real alerts.** v0.1.0 has only been exercised on synthetic data.

## Demo

Runs entirely on the synthetic fixture; no real data is touched.

```console
$ python -m pip install -e ".[dev]"
$ make demo
# equivalent to:
$ catalog-enrich enrich --snapshot tests/fixtures/mini_snapshot.jsonl examples/alerts_synthetic.csv
$ catalog-enrich lookup --snapshot tests/fixtures/mini_snapshot.jsonl geodo "Xtreme RAT" sharedalias
```

Against your own pinned snapshot:

```console
$ catalog-enrich enrich --snapshot /path/to/data/malware_families.jsonl \
      --family-column family alerts.csv -o alerts.enriched.csv
# or
$ make enrich SNAPSHOT=/path/to/data/malware_families.jsonl INPUT=alerts.csv OUTPUT=alerts.enriched.csv
```

`metadata.json` is read from the snapshot's directory by default (override with `--metadata`).

## Contract

### Input snapshot

JSON Lines, one object per line (UTF-8, BOM tolerated). Fields read (schema_version 1.1.0):

| Field | Type | Used for |
| --- | --- | --- |
| `family` | string, required | primary key (exact + normalized match) |
| `aliases` | list of strings | alias match |
| `category` | string | `category_raw`, `category_normalized` |
| `enrichment_level` | string | `enrichment_level` (curation signal) |
| `sample_count` | int | `sample_count` |
| `mitre_attack` | list of technique IDs | `mitre_attack` |
| `mitre_attack_detail` | list of `{id, name, tactic?}` | merged into `mitre_attack` (IDs only) |
| `threat_actors` | list of strings | `threat_actors` |
| `motivation` | string | `motivation` |
| `containment_steps` | list of strings | `containment_step_count` |
| `references`, `sources`, `cisa_advisory`, `mitre_url` | mixed | `has_reference_url` |
| `last_updated` | string | `last_updated` |

Other fields are ignored. A snapshot with no string `family` field fails fast.

### Matching

Normalization: Unicode NFKC, casefold, drop every non-alphanumeric character
(`"Xtreme RAT"`, `"xtreme-rat"`, `"XTREMERAT"` share one key).

Resolution order and `match_method` values:

1. `exact`: literal `family` match
2. `normalized`: normalized `family` match
3. `alias`: normalized alias match
4. `ambiguous`: key maps to more than one family; no record, `candidates` lists them
5. `none`: no match, empty or non-string input

### Output

`lookup` prints JSON (one object, or a list for several names) with `query`, `match_method`, the
mapped fields above, `candidates`, and a `provenance` object. Exit code 0 if every name matched,
1 if any was `none`/`ambiguous`, 2 on usage or snapshot errors.

`enrich` copies every input column unchanged and appends, in this order:

`ce_match_method, ce_matched_family, ce_category_raw, ce_category_normalized,
ce_category_mapping_status, ce_enrichment_level, ce_sample_count, ce_aliases, ce_mitre_attack,
ce_threat_actors, ce_motivation, ce_containment_step_count, ce_has_reference_url,
ce_last_updated, ce_snapshot_sha256, ce_metadata_schema_version, ce_mapping_version`

Lists are `;`-joined, booleans are `true`/`false`, missing values are empty. The command refuses to
run if the input already has a `ce_*` column it would write.

### Provenance

Every result carries: `snapshot_path`, `snapshot_sha256`, `snapshot_bytes`, `record_count`,
`metadata_path`, `metadata_schema_version`, `mapping_version`, `tool_version`, and
`status: "reference-only"`. The hash is computed over the exact bytes that were parsed.
Note that the metadata's own counts can differ from the parsed `record_count`; the parsed count
is what is reported.

## Development

```console
$ make install   # editable install with dev extras
$ make lint      # ruff check + ruff format --check
$ make test      # pytest
```

## License

Apache-2.0. See [LICENSE](LICENSE).
