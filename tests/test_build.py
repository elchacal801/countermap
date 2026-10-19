import json
import os
import sqlite3

import pytest

from countermap.ingest import BuildError, build, prev_path

from conftest import (
    UNRESOLVABLE_DC_REF,
    attack_bundle,
    detection_objects,
    ics_bundle,
    ics_detection_objects,
    write_fixtures,
)


def test_analytic_references_resolve_across_attack_bundles(detect_db):
    from countermap.query import Countermap

    # AN0200 is in the ICS bundle; the data component it references is published only in the Enterprise bundle.
    c = Countermap(detect_db)
    assert c.lookup("AN0200")["log_sources"] == [
        {"data_component": "DC0001 Web Credential Usage", "name": "IdP:SignIn", "channel": "workstation logon"}]
    assert rows(detect_db, "SELECT source FROM edges WHERE src = 'attack:AN0200' AND rel = 'uses_data_component'") == [
        {"source": "attack-ics"}]
    assert c.telemetry_coverage(log_sources=["IdP:SignIn"], techniques=["T0001"])["counts"]["covered"] == 1


def test_unresolvable_analytic_reference_is_a_build_warning(detect_db):
    warnings = json.loads(rows(detect_db, "SELECT value FROM meta WHERE key = 'warnings'")[0]["value"])
    hits = [w for w in warnings if "AN0201" in w]
    assert len(hits) == 1 and UNRESOLVABLE_DC_REF in hits[0] and "historian:applog" in hits[0]
    assert not rows(detect_db, "SELECT * FROM edges WHERE src = 'attack:AN0201' AND rel = 'uses_data_component'")


def test_cross_bundle_references_do_not_depend_on_load_order(tmp_path, monkeypatch):
    from countermap import ingest

    def links(db):
        return sorted((r["src"], r["dst"], r["source"], r["detail"]) for r in rows(
            db, "SELECT src, dst, source, detail FROM edges WHERE rel = 'uses_data_component'"))

    bundles = {"attack": attack_bundle(extra_objects=detection_objects()),
               "ics": ics_bundle(extra_objects=ics_detection_objects())}
    usual = tmp_path / "usual.db"
    build(usual, write_fixtures(tmp_path / "a", **bundles), tmp_path / "cache", log=lambda m: None)
    monkeypatch.setattr(ingest, "ORDER", ["attack-ics", *[k for k in ingest.ORDER if k != "attack-ics"]])
    ics_first = tmp_path / "ics_first.db"
    build(ics_first, write_fixtures(tmp_path / "b", **bundles), tmp_path / "cache", log=lambda m: None)
    assert links(usual) == links(ics_first)
    assert ("attack:AN0200", "attack:DC0001") in {(src, dst) for src, dst, *_ in links(ics_first)}


def rows(db, sql, *params):
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    out = [dict(r) for r in conn.execute(sql, params)]
    conn.close()
    return out


def test_sources_recorded_with_versions_and_hashes(built):
    src = {r["key"]: r for r in rows(built, "SELECT * FROM sources")}
    assert src["attack-enterprise"]["version"] == "20.0"
    assert src["f3"]["version"] == "1.2"
    assert src["atlas"]["version"] == "2026.09"
    assert src["d3fend-ontology"]["version"] == "9.9.9"
    assert all(r["status"] == "loaded" and len(r["sha256"]) == 64 for r in src.values())


def test_every_stored_edge_is_official_with_a_source(built):
    edges = rows(built, "SELECT provenance, source FROM edges")
    assert edges and all(e["provenance"] == "official" and e["source"] for e in edges)


def test_legacy_mitigation_does_not_shadow_technique(built):
    t = rows(built, "SELECT kind, name FROM nodes WHERE id = 'attack:T1539'")[0]
    assert t == {"kind": "technique", "name": "Steal Web Session Cookie"}
    legacy = rows(built, "SELECT kind, deprecated FROM nodes WHERE id = 'attack:mitigation:T1539'")[0]
    assert legacy == {"kind": "mitigation", "deprecated": 1}


def test_cross_domain_id_collision_is_isolated_and_reported(built):
    assert rows(built, "SELECT name FROM nodes WHERE id = 'attack:S0001'")[0]["name"] == "CookieGrabber"
    assert rows(built, "SELECT name FROM nodes WHERE id = 'attack:S0001@ics-attack'")[0]["name"] == "LegacyThing"
    warnings = json.loads(rows(built, "SELECT value FROM meta WHERE key = 'warnings'")[0]["value"])
    assert any("reuses S0001" in w for w in warnings)


def test_deprecated_relationships_are_skipped(built):
    assert not rows(built, "SELECT * FROM edges WHERE src = 'attack:G0016' AND dst = 'attack:T1684'")


def test_f3_objects_stay_in_their_namespace_and_link_to_attack(built):
    f3 = rows(built, "SELECT * FROM nodes WHERE id = 'f3:T1566'")[0]
    assert f3["framework"] == "f3" and f3["source"] == "f3"
    links = {r["dst"]: json.loads(r["detail"] or "{}") for r in rows(
        built, "SELECT dst, detail FROM edges WHERE rel = 'reuses_attack_id'")}
    assert "attack:T1566" in links
    assert links["attack:T1586.004"]["target_missing"] is True
    assert links["attack:T1656"]["target_revoked"] is True
    assert links["attack:T1656"]["revoked_by"] == ["attack:T1684.001"]


def test_d3fend_entities_tactics_and_kinds(built):
    cm = {r["ext_id"]: r for r in rows(built, "SELECT ext_id, kind, extra FROM nodes WHERE framework = 'd3fend'")}
    assert json.loads(cm["D3-CH"]["extra"])["tactic"] == "Harden"
    assert json.loads(cm["D3-MFA"]["extra"])["tactic"] == "Harden"  # inherited from parent
    assert json.loads(cm["D3-UA"]["extra"])["tactic"] == "Detect"  # restriction form, ID whitespace stripped
    assert cm["D3A-CA"]["kind"] == "analytic-technique"
    assert cm["SessionCookie"]["kind"] == "artifact"


def test_d3fend_mappings_become_counters_edges(built):
    counters = rows(built, "SELECT src, dst FROM edges WHERE rel = 'counters'")
    pairs = {(r["src"], r["dst"]) for r in counters}
    assert ("d3fend:D3-CH", "attack:T1539") in pairs
    assert ("d3fend:D3-UA", "attack:T1566.002") in pairs
    assert not any("CAPEC" in r["dst"] for r in counters)


def test_rebuild_keeps_previous_snapshot(tmp_path):
    db = tmp_path / "x.db"
    build(db, write_fixtures(tmp_path / "a"), tmp_path / "cache", log=lambda m: None)
    build(db, write_fixtures(tmp_path / "b", attack=attack_bundle(version="20.1")), tmp_path / "cache", log=lambda m: None)
    assert prev_path(db).exists()
    assert rows(prev_path(db), "SELECT version FROM sources WHERE key='attack-enterprise'")[0]["version"] == "20.0"
    assert rows(db, "SELECT version FROM sources WHERE key='attack-enterprise'")[0]["version"] == "20.1"


def test_missing_optional_mappings_is_recorded_not_fatal(c_no_mappings):
    assert c_no_mappings._mapping_status() == "unavailable"


def test_changed_mappings_format_fails_loudly(tmp_path):
    from countermap.query import Countermap

    sources = write_fixtures(tmp_path / "src")
    mappings = tmp_path / "src" / "mappings.json"
    doc = json.loads(mappings.read_text())
    for row in doc["results"]["bindings"]:
        for key in [k for k in row if k.startswith("def_")]:
            row["renamed_" + key] = row.pop(key)
    mappings.write_text(json.dumps(doc))
    db = tmp_path / "x.db"
    build(db, sources, tmp_path / "cache", log=lambda m: None)
    c = Countermap(db)
    assert c._mapping_status() == "failed"
    assert any("format not recognized" in w for w in c.datasets()["warnings"])
    assert "unavailable, not empty" in c.countermeasures("T1539")["notes"][-1]


def test_unresolved_optional_source_is_recorded_unavailable(tmp_path):
    from countermap.query import Countermap

    sources = write_fixtures(tmp_path / "src")
    next(s for s in sources if s.key == "d3fend-mappings").url = None
    db = tmp_path / "x.db"
    build(db, sources, tmp_path / "cache", log=lambda m: None)
    src = {r["key"]: r for r in rows(db, "SELECT * FROM sources")}
    assert src["d3fend-mappings"]["status"] == "unavailable"
    assert "no URL could be resolved" in src["d3fend-mappings"]["note"]
    assert "unavailable, not empty" in Countermap(db).countermeasures("T1539")["notes"][-1]


@pytest.mark.parametrize("key", ["d3fend-ontology", "f3", "attack-enterprise"])
def test_unavailable_required_source_fails_the_build_and_keeps_the_previous_database(tmp_path, key):
    db = tmp_path / "x.db"
    build(db, write_fixtures(tmp_path / "a"), tmp_path / "cache", log=lambda m: None)
    before = db.read_bytes()
    sources = write_fixtures(tmp_path / "b")
    next(s for s in sources if s.key == key).url = str(tmp_path / "missing" / "source.file")
    logged = []
    with pytest.raises(BuildError, match=f"required source {key} could not be fetched"):
        build(db, sources, tmp_path / "cache", log=logged.append)
    assert f"  ! {key}: unavailable (required)" in logged
    assert db.read_bytes() == before and not prev_path(db).exists()
    assert not db.with_name(db.name + ".building").exists()


@pytest.mark.parametrize("key,filename,content", [
    ("d3fend-ontology", "d3fend.ttl", "this is not turtle @@@"),
    ("atlas", "atlas.yaml", "techniques: ["),
])
def test_unparsable_required_source_fails_the_build(tmp_path, key, filename, content):
    db = tmp_path / "x.db"
    sources = write_fixtures(tmp_path / "src")
    (tmp_path / "src" / filename).write_text(content)
    with pytest.raises(BuildError, match=f"{key}: could not ingest"):
        build(db, sources, tmp_path / "cache", log=lambda m: None)
    assert not db.exists() and not db.with_name(db.name + ".building").exists()


def _without(sources, tmp_path, *keys):
    for s in sources:
        if s.key in keys:
            s.url = str(tmp_path / "unreachable" / f"{s.key}.file")
    return sources


def test_allow_partial_builds_without_required_sources_and_marks_the_database_degraded(tmp_path):
    from countermap.query import Countermap

    db = tmp_path / "x.db"
    logged = []
    sources = _without(write_fixtures(tmp_path / "src"), tmp_path, "d3fend-ontology")
    build(db, sources, tmp_path / "cache", allow_partial=True, log=logged.append)
    assert "  ! d3fend-ontology: unavailable (required; built without it because of --allow-partial)" in logged
    c = Countermap(db)
    data = c.datasets()
    assert data["degraded"] is True
    missing = {m["key"]: m for m in data["missing_sources"]}
    assert missing["d3fend-ontology"]["status"] == "unavailable" and missing["d3fend-ontology"]["required"] is True
    # The mappings need the ontology, so they are recorded as not loaded rather than left out.
    assert missing["d3fend-mappings"]["status"] == "unavailable" and missing["d3fend-mappings"]["required"] is False
    assert "ontology was not loaded" in missing["d3fend-mappings"]["note"]
    assert any("degraded" in w and "d3fend-ontology" in w for w in data["warnings"])
    assert c.lookup("T1539")["name"] == "Steal Web Session Cookie"
    assert c.countermeasures("T1539")["gap_reason"] == "unavailable"
    gaps = c.coverage_gaps(["T1539"])
    assert gaps["summary"]["d3fend_unavailable"] == ["T1539"] and gaps["techniques"][0]["d3fend_official"] is None


def test_allow_partial_records_an_unparsable_required_source_as_failed(tmp_path):
    from countermap.query import Countermap

    db = tmp_path / "x.db"
    sources = write_fixtures(tmp_path / "src")
    (tmp_path / "src" / "atlas.yaml").write_text("techniques: [")
    build(db, sources, tmp_path / "cache", allow_partial=True, log=lambda m: None)
    data = Countermap(db).datasets()
    assert data["degraded"] is True
    assert [(m["key"], m["status"], m["required"]) for m in data["missing_sources"]] == [("atlas", "failed", True)]


def test_a_source_that_fails_midway_contributes_nothing(tmp_path, monkeypatch):
    from countermap import ingest

    def half_then_fail(writer, path, key):
        writer.add_node("atlas:AML.T9999", framework="atlas", kind="technique", ext_id="AML.T9999",
                        name="Half-written", source=key)
        raise KeyError("techniques")

    monkeypatch.setattr(ingest, "ingest_atlas", half_then_fail)
    db = tmp_path / "x.db"
    build(db, write_fixtures(tmp_path / "src"), tmp_path / "cache", allow_partial=True, log=lambda m: None)
    assert rows(db, "SELECT id FROM nodes WHERE source = 'atlas'") == []
    assert rows(db, "SELECT status FROM sources WHERE key = 'atlas'") == [{"status": "failed"}]


def test_allow_partial_still_fails_on_a_hash_mismatch(tmp_path):
    sources = write_fixtures(tmp_path / "src")
    next(s for s in sources if s.key == "f3").sha256 = "0" * 64
    with pytest.raises(BuildError, match="SHA-256 mismatch"):
        build(tmp_path / "x.db", sources, tmp_path / "cache", verify_hashes=True, allow_partial=True,
              log=lambda m: None)


def test_complete_builds_are_not_degraded(c, c_no_mappings):
    assert c.datasets()["degraded"] is False and c.datasets()["missing_sources"] == []
    data = c_no_mappings.datasets()
    assert data["degraded"] is False
    assert [(m["key"], m["status"], m["required"]) for m in data["missing_sources"]] == [
        ("d3fend-mappings", "unavailable", False)]


def test_cli_build_fails_on_a_missing_required_source_unless_allow_partial(tmp_path, capsys):
    from countermap import cli
    from countermap.sources import write_lock

    db, cache = tmp_path / "x.db", tmp_path / "cache"
    complete = tmp_path / "complete.lock.json"
    write_lock(complete, write_fixtures(tmp_path / "src"))
    assert cli.main(["--db", str(db), "build", "--lock", str(complete), "--cache", str(cache)]) == 0
    before = db.read_bytes()
    capsys.readouterr()

    blocked = tmp_path / "blocked.lock.json"
    write_lock(blocked, _without(write_fixtures(tmp_path / "src"), tmp_path, "d3fend-ontology", "d3fend-mappings"))
    assert cli.main(["--db", str(db), "build", "--lock", str(blocked), "--cache", str(cache)]) == 3
    err = capsys.readouterr().err
    assert "required source d3fend-ontology could not be fetched" in err and "--allow-partial" in err
    assert db.read_bytes() == before

    assert cli.main(["--db", str(db), "build", "--lock", str(blocked), "--cache", str(cache), "--allow-partial"]) == 0
    err = capsys.readouterr().err
    assert "degraded" in err and "d3fend-ontology" in err and "unavailable" in err
    assert cli.main(["--db", str(db), "info"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["degraded"] is True
    assert {m["key"] for m in info["missing_sources"]} == {"d3fend-ontology", "d3fend-mappings"}


def test_read_only_open_survives_odd_paths(tmp_path):
    from countermap.query import Countermap

    # Windows does not allow "?" in file names, so only "#" and "%" can be exercised there.
    odd = tmp_path / ("we#ird%dir" if os.name == "nt" else "we#ird?dir%")
    db = odd / "x.db"
    build(db, write_fixtures(tmp_path / "src"), tmp_path / "cache", log=lambda m: None)
    assert Countermap(db).lookup("T1539")["name"] == "Steal Web Session Cookie"
