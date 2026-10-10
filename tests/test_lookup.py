import csv
import hashlib
import io
import json
from pathlib import Path

import pytest

from catalog_enrich import Catalog, map_record, normalize_name
from catalog_enrich.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOT = FIXTURES / "mini_snapshot.jsonl"
EXAMPLE_CSV = Path(__file__).parent.parent / "examples" / "alerts_synthetic.csv"


@pytest.fixture(scope="module")
def cat():
    return Catalog.from_jsonl(SNAPSHOT)


def test_normalize_name():
    assert normalize_name("  Xtreme RAT ") == "xtremerat"
    assert normalize_name("xtreme-rat") == "xtremerat"
    assert normalize_name("Zeus_Panda") == "zeuspanda"
    assert normalize_name(None) == ""
    assert normalize_name("---") == ""


def test_exact_match(cat):
    r = cat.lookup("emotet")
    assert r.match_method == "exact"
    assert r.record["family"] == "emotet"


def test_normalized_family_match(cat):
    r = cat.lookup("  EMOTET ")
    assert r.match_method == "normalized"
    assert r.record["family"] == "emotet"


def test_alias_match_case_and_separators(cat):
    assert cat.lookup("Geodo").record["family"] == "emotet"
    assert cat.lookup("zeus panda").record["family"] == "zbot"
    r = cat.lookup("Xtreme-RAT")
    assert r.match_method == "alias"
    assert r.record["family"] == "xtrat"


def test_family_beats_alias(cat):
    # "Zbot" is both the family key (normalized) and an alias of the same record
    r = cat.lookup("Zbot")
    assert r.match_method == "normalized"
    assert r.record["family"] == "zbot"


def test_ambiguous_alias_returns_no_record(cat):
    r = cat.lookup("sharedalias")
    assert r.match_method == "ambiguous"
    assert r.record is None
    assert r.candidates == ["installmonster", "wannacry"]
    assert "sharedalias" in cat.alias_collisions()


@pytest.mark.parametrize("query", ["notafamily", "", "   ", None, 42])
def test_no_match(cat, query):
    r = cat.lookup(query)
    assert r.match_method == "none"
    assert r.record is None


def test_provenance_on_every_result(cat):
    expected = hashlib.sha256(SNAPSHOT.read_bytes()).hexdigest()
    for q in ["emotet", "notafamily", "sharedalias"]:
        prov = cat.lookup(q).as_dict()["provenance"]
        assert prov["snapshot_sha256"] == expected
        assert prov["metadata_schema_version"] == "1.1.0"
        assert prov["record_count"] == 6
        assert prov["status"] == "reference-only"
        assert prov["mapping_version"]


def test_missing_metadata_is_tolerated(tmp_path):
    snap = tmp_path / "snap.jsonl"
    snap.write_bytes(SNAPSHOT.read_bytes())
    c = Catalog.from_jsonl(snap)
    assert c.provenance.metadata_schema_version is None
    assert c.provenance.metadata_path is None


def test_mapping_fields(cat):
    m = map_record(cat.lookup("emotet").record)
    assert m["category_raw"] == "loader"
    assert m["category_normalized"] is None
    assert m["category_mapping_status"] == "unmapped"
    assert m["mitre_attack"] == ["T1566.001", "T1059.001", "T1547.001"]
    assert m["containment_step_count"] == 2
    assert m["has_reference_url"] is True
    z = map_record(cat.lookup("zbot").record)
    assert z["category_normalized"] == "banker"
    assert z["has_reference_url"] is False
    assert "cta" not in m and "description" not in m


def test_map_none_has_all_fields():
    from catalog_enrich.mapping import OUTPUT_FIELDS

    assert set(map_record(None)) == set(OUTPUT_FIELDS)


def test_invalid_snapshot(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"family": "a"}\nnot json\n', encoding="utf-8")
    with pytest.raises(ValueError):
        Catalog.from_jsonl(bad)


def test_cli_lookup(capsys):
    rc = main(["lookup", "--snapshot", str(SNAPSHOT), "geodo"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["matched_family"] == "emotet"
    assert out["match_method"] == "alias"


def test_cli_lookup_nonzero_on_miss(capsys):
    assert main(["lookup", "--snapshot", str(SNAPSHOT), "notafamily"]) == 1


def test_cli_enrich(tmp_path):
    out = tmp_path / "out.csv"
    rc = main(["enrich", "--snapshot", str(SNAPSHOT), str(EXAMPLE_CSV), "-o", str(out)])
    assert rc == 0
    rows = list(csv.DictReader(io.StringIO(out.read_text(encoding="utf-8"))))
    assert [r["ce_match_method"] for r in rows] == ["exact", "alias", "alias", "ambiguous", "none"]
    assert rows[1]["ce_matched_family"] == "zbot"
    assert rows[0]["alert_id"] == "S001"
    assert len({r["ce_snapshot_sha256"] for r in rows}) == 1
    assert rows[4]["ce_matched_family"] == ""


def test_cli_enrich_missing_column(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("id,name\n1,emotet\n", encoding="utf-8")
    assert main(["enrich", "--snapshot", str(SNAPSHOT), str(src)]) == 2
