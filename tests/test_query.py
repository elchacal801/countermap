import pytest

from countermap.query import NotFound


@pytest.mark.parametrize("ref,expected", [
    ("T1566.002", "attack:T1566.002"),
    ("t1566.002", "attack:T1566.002"),
    ("Cozy Bear", "attack:G0016"),
    ("APT29", "attack:G0016"),
    ("f3:T1566", "f3:T1566"),
    ("F1005.006", "f3:F1005.006"),
    ("T1586.004", "f3:T1586.004"),  # only F3 has it, so fall back to F3
    ("AML.T0051", "atlas:AML.T0051"),
    ("D3-CH", "d3fend:D3-CH"),
    ("Harden", "d3fend:Harden"),
])
def test_parse_ref(c, ref, expected):
    assert c.parse_ref(ref) == expected


def test_unknown_ref_suggests(c):
    with pytest.raises(NotFound) as err:
        c.parse_ref("Spearphishing")
    assert "did you mean" in str(err.value)


def test_revoked_ids_resolve_with_warning(c):
    out = c.lookup("T1656")
    assert out["id"] == "attack:T1684.001"
    assert "revoked" in out["warnings"][0]


def test_search_excludes_inactive_by_default(c):
    ids = [r["id"] for r in c.search("Impersonation")["results"]]
    assert "attack:T1684.001" in ids and "attack:T1656" not in ids
    assert "attack:T1656" in [r["id"] for r in c.search("Impersonation", include_inactive=True)["results"]]


def test_technique_context(c):
    ctx = c.technique_context("T1539")
    assert ctx["tactics"][0]["name"] == "Credential Access"
    assert ctx["used_by"]["campaign"]["items"] == ["C0001 Operation Test"]
    det = ctx["detection_strategies"][0]
    assert det["id"] == "DET0001"
    assert det["analytics"][0]["log_sources"][0] == {
        "data_component": "DC0001 Web Credential Usage", "name": "IdP:SignIn", "channel": "token replay"}
    assert ctx["d3fend"]["total"] == 2


def test_mitigations_are_the_mitre_links_to_a_technique(c):
    assert c.mitigations("attack:T1566.002") == [{"id": "M1017", "name": "User Training", "framework": "attack"}]
    assert c.mitigations("atlas:AML.T0051") == [
        {"id": "AML.M0015", "name": "Adversarial Input Detection", "framework": "atlas"}]
    # The pre-2019 "Steal Web Session Cookie Mitigation" is deprecated, so it is not listed.
    assert c.mitigations("attack:T1539") == []
    assert c.technique_context("T1566.002")["mitigations"] == ["M1017 User Training"]


def test_detection_strategies_carry_analytics_and_log_sources(c):
    assert c.detection_strategies("attack:T1539") == [{
        "id": "DET0001", "name": "Detect cookie replay",
        "analytics": [{"id": "AN0001", "platforms": ["Identity Provider"], "log_sources": [
            {"data_component": "DC0001 Web Credential Usage", "name": "IdP:SignIn", "channel": "token replay"}]}],
    }]
    assert c.detection_strategies("attack:T1566.002") == []


def test_countermeasures_official_first(c):
    out = c.countermeasures("T1539")
    assert out["status"] == "loaded"
    assert {m["d3fend_id"] for m in out["countermeasures"]} == {"D3-CH", "D3-MFA"}
    assert all(m["provenance"] == "official" for m in out["countermeasures"])
    assert out["countermeasures"][0]["paths"][0]["off_artifact"] == "Session Cookie"


def test_countermeasures_derived_from_subtechnique(c):
    out = c.countermeasures("T1566")
    assert [(m["d3fend_id"], m["provenance"]) for m in out["countermeasures"]] == [("D3-UA", "derived")]
    assert "sub-technique attack:T1566.002" in out["countermeasures"][0]["via"]


def test_countermeasures_through_revoked_id(c):
    out = c.countermeasures("T1684.001")
    ch = next(m for m in out["countermeasures"] if m["d3fend_id"] == "D3-CH")
    assert ch["provenance"] == "derived" and "revoked ID attack:T1656" in ch["via"]
    # D3FEND can keep mapping an ID long after ATT&CK revoked it; the label must not claim otherwise.
    assert "D3FEND still maps the old ID" in ch["via"] and "predates" not in ch["via"]


def test_countermeasures_for_f3_reused_and_native(c):
    reused = c.countermeasures("f3:T1566")
    assert reused["countermeasures"] and all(m["provenance"] == "derived" for m in reused["countermeasures"])
    assert "F3 reuses ATT&CK ID attack:T1566" in reused["countermeasures"][0]["via"]
    native = c.countermeasures("F1005.006")
    assert native["total"] == 0 and "F3-native" in native["notes"][0]


def test_countermeasures_for_f3_link_to_revoked_attack_id(c):
    out = c.countermeasures("f3:T1656")
    assert any("replaced by attack:T1684.001" in (m["via"] or "") for m in out["countermeasures"])


def test_countermeasures_when_mappings_unavailable(c_no_mappings):
    out = c_no_mappings.countermeasures("T1539")
    assert out["status"] == "unavailable" and out["total"] == 0
    assert "unavailable, not empty" in out["notes"][-1]


def test_gap_note_distinguishes_unknown_to_d3fend(c):
    out = c.countermeasures("T1684")
    assert any("not in the loaded D3FEND ontology" in n for n in out["notes"])


def test_crosswalk_atlas(c):
    out = c.crosswalk("AML.T0073")
    link = out["links"][0]
    assert link["id"] == "attack:T1656" and link["target_revoked"] is True and link["provenance"] == "official"


def test_actor_techniques_and_software_derivation(c):
    direct = c.actor_techniques("APT29")
    assert [t["id"] for t in direct["techniques"]] == ["T1566.002"]
    full = c.actor_techniques("APT29", include_software=True)
    via = {t["id"]: t for t in full["techniques"]}
    assert via["T1539"]["provenance"] == "derived" and via["T1539"]["via"] == "software S0001"


def test_compare_actors(c):
    out = c.compare_actors(["G0016", "Fancy Bear"])
    assert out["shared_by_all"] == ["T1566.002"]
    assert out["unique"]["G0007"] == ["T1684.001"]


def test_coverage_gaps(c):
    out = c.coverage_gaps(["T1566.002", "T1539", "T1684", "F1005", "T9999"])
    assert out["summary"]["not_found_or_not_technique"] == ["T9999"]
    assert "T1684" in out["summary"]["no_official_d3fend"]
    assert "T1539" in out["summary"]["no_mitigation"]
    assert "T1566.002" not in out["summary"]["no_mitigation"]


def test_datasets(c):
    data = c.datasets()
    assert data["active_object_counts"]["attack"]["technique"] == 6  # 5 Enterprise + 1 ICS
    assert any("missing" in w for w in data["warnings"])


def test_name_ambiguity_is_reported(c):
    node_id, warnings = c._parse("Impersonation")
    assert node_id == "attack:T1684.001"  # ATT&CK preferred over F3, active over revoked
    assert warnings and "matches 3 objects" in warnings[0] and "f3:T1656" in warnings[0] and "atlas:AML.T0073" in warnings[0]


def test_countermeasures_rejects_non_techniques(c):
    with pytest.raises(NotFound, match="not a technique"):
        c.countermeasures("G0016")
    with pytest.raises(NotFound, match="unknown D3FEND tactic"):
        c.countermeasures("T1539", tactic="Hardenn")
    out = c.countermeasures("T1539", tactic="Detect")
    assert out["total"] == 0 and "none in tactic Detect" in out["notes"][0]


def test_technique_context_shows_provenance(c):
    ctx = c.technique_context("T1566")
    assert ctx["d3fend"]["official"] == 0 and ctx["d3fend"]["derived"] == 1
    assert ctx["d3fend"]["countermeasures"][0]["via"].startswith("sub-technique")


def test_coverage_gaps_rejects_non_techniques(c):
    out = c.coverage_gaps(["G0016", "D3-MFA"])
    assert out["summary"]["not_found_or_not_technique"] == ["G0016", "D3-MFA"]


def test_long_and_noisy_inputs(c):
    with pytest.raises(NotFound, match="longer than"):
        c.parse_ref("x" * 100_000)
    import time
    t = time.time()
    c.search(" ".join(f"term{i}" for i in range(5000)))
    assert time.time() - t < 2


def test_parallel_queries_are_consistent(c):
    from concurrent.futures import ThreadPoolExecutor
    expected = c.actor_techniques("APT28")["total"]
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: c.actor_techniques("APT28")["total"], range(200)))
    assert set(results) == {expected}


def test_ics_targets_edges(c):
    assert c.technique_context("T0001")["targets_assets"] == ["A0001 Workstation"]


def test_d3fend_duplicate_ids_are_kept_apart(c):
    a = c.lookup("D3A-CA")
    b = c.lookup("d3fend:D3A-CA@CorrelationAnalysis")
    assert a["name"] == "Cluster Analysis" and b["name"] == "Correlation Analysis"
    assert any("1 D3FEND IDs are assigned to more than one class" in w and "D3A-CA" in w
               for w in c.datasets()["warnings"])
