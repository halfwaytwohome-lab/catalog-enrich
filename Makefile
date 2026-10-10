PYTHON ?= python
SNAPSHOT ?=
INPUT ?=
OUTPUT ?= -
FAMILY_COLUMN ?= family
FIXTURE := tests/fixtures/mini_snapshot.jsonl

.PHONY: install test lint format demo enrich clean

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m ruff format --check src tests

format:
	$(PYTHON) -m ruff format src tests
	$(PYTHON) -m ruff check --fix src tests

# Synthetic data only.
demo:
	$(PYTHON) -m catalog_enrich.cli enrich --snapshot $(FIXTURE) examples/alerts_synthetic.csv
	-$(PYTHON) -m catalog_enrich.cli lookup --snapshot $(FIXTURE) geodo "Xtreme RAT" sharedalias

# make enrich SNAPSHOT=path/to/malware_families.jsonl INPUT=alerts.csv [OUTPUT=out.csv]
enrich:
	@test -n "$(SNAPSHOT)" || (echo "SNAPSHOT=path/to/malware_families.jsonl is required" && exit 2)
	@test -n "$(INPUT)" || (echo "INPUT=path/to/alerts.csv is required" && exit 2)
	$(PYTHON) -m catalog_enrich.cli enrich --snapshot "$(SNAPSHOT)" --family-column "$(FAMILY_COLUMN)" "$(INPUT)" -o "$(OUTPUT)"

clean:
	rm -rf build dist .pytest_cache .ruff_cache src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
