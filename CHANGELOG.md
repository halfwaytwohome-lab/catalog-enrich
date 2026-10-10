# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-10

Rebuilt from scratch: the original v0.1.0 archive could not be located, so this release is a
clean reconstruction against the catalog's schema_version 1.1.0 record layout.

### Added
- `Catalog.from_jsonl()`: in-memory index over a pinned JSONL snapshot.
- Normalized (NFKC + casefold + alphanumeric-only), alias-aware lookup with
  `exact` / `normalized` / `alias` / `ambiguous` / `none` match methods; ambiguous keys never
  return a record.
- Field mapping to a stable enrichment output, with category normalization carried over from
  the Phase 0 inspection policy (raw category preserved).
- Provenance (snapshot path, SHA-256, size, record count, metadata schema version, mapping
  version, tool version, `reference-only` status) attached to every result.
- `catalog-enrich lookup` and `catalog-enrich enrich` CLI commands.
- Synthetic test fixture, pytest suite, ruff lint, GitHub Actions CI matrix (3.9 to 3.13).

<!-- TODO(repo-url): add compare links once the repository exists, e.g.
[Unreleased]: https://github.com/OWNER/catalog-enrich/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER/catalog-enrich/releases/tag/v0.1.0
-->
