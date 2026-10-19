import json

import pytest
from pydantic import ValidationError

from countermap.diff import diff_snapshots
from countermap.emit import render
from countermap.emit.cad import calibrate_from_export, render_cad
from countermap.emit.navigator import F3_DATA_URL, f3_data_url, navigator_layers
from countermap.emit.validate import validate_attack_flow, validate_cad
from countermap.ingest import build
from countermap.query import NotFound
from countermap.scenario import resolve_scenario

from conftest import attack_bundle, technique, write_fixtures

SPEC = {
    "title": "Cookie theft to payment change",
    "description": "test",
    "authors": ["tester"],
    "steps": [
        {"id": "s1", "technique": "T1566.002", "description": "link"},
        {"id": "s2", "technique": "T1539", "after": ["s1"], "assets": ["Mailbox"]},
        {"id": "s3", "technique": "T1656", "after": ["s2"]},
        {"id": "s4", "technique": "F1005.006", "after": ["s3"]},
    ],
    "countermeasures": "auto",
    "max_countermeasures_per_step": 2,
}
TS = "2026-10-15T00:00:00.000Z"


def test_render_all_formats_validate(c):
    out = render(SPEC, c, timestamp=TS)
    assert not validate_cad(out["cad"])
    assert not validate_attack_flow(out["attack_flow"])
    assert "flowchart LR" in out["mermaid"]
    assert set(out["navigator"]) == {"enterprise-attack", "f3-financial"}
    assert any("T1656 is revoked" in w for w in out["warnings"])


def test_render_lists_mitre_mitigations_per_step(c):
    out = render(SPEC, c, ["mermaid"], timestamp=TS)
    assert [m["step"] for m in out["step_mitigations"]] == ["s1", "s2", "s3", "s4"]
    by_step = {m["step"]: m for m in out["step_mitigations"]}
    assert by_step["s1"] == {"step": "s1", "technique": "T1566.002",
                             "mitigations": [{"id": "M1017", "name": "User Training", "framework": "attack"}]}
    assert by_step["s4"] == {"step": "s4", "technique": "F1005.006", "mitigations": []}


def test_scenario_navigator_layer_carries_mitigations(c):
    layer = render(SPEC, c, ["navigator"], timestamp=TS)["navigator"]["enterprise-attack"]
    entries = {t["techniqueID"]: t for t in layer["techniques"]}
    assert {"name": "mitigation", "value": "M1017 User Training"} in entries["T1566.002"]["metadata"]
    assert {"name": "detection", "value": "DET0001 Detect cookie replay"} in entries["T1539"]["metadata"]


def test_render_lists_detection_strategies_per_step(c):
    out = render(SPEC, c, ["mermaid"], timestamp=TS)
    assert [d["step"] for d in out["step_detections"]] == ["s1", "s2", "s3", "s4"]
    by_step = {d["step"]: d for d in out["step_detections"]}
    assert by_step["s2"] == {"step": "s2", "technique": "T1539", "detection_strategies": [{
        "id": "DET0001", "name": "Detect cookie replay", "platforms": ["Identity Provider"],
        "log_sources": [{"log_source": "IdP:SignIn", "channel": "token replay",
                         "data_component": "DC0001 Web Credential Usage", "platforms": ["Identity Provider"]}],
        "analytics": [{"id": "AN0001", "platforms": ["Identity Provider"], "description": None, "tunables": []}]}]}
    assert by_step["s4"]["detection_strategies"] == []


def test_cad_structure(c):
    cad = render(SPEC, c, ["cad"], timestamp=TS)["cad"]
    types = {n["type"] for n in cad["nodes"]}
    assert types == {"attack-node", "artifact-node", "countermeasure-node"}
    by_label = {n["data"]["label"]: n for n in cad["nodes"]}
    assert by_label["T1539 Steal Web Session Cookie"]["data"]["d3f_class"] == "d3f:T1539"
    assert "d3f_class" not in by_label["F1005.006 Account Manipulation: Change of Payment Details"]["data"]
    assert by_label["Credential Hardening (D3-CH)"]["data"]["d3f_class"] == "d3f:CredentialHardening"
    props = {e["data"]["label"]: e["data"].get("d3f_property") for e in cad["edges"]}
    assert props["precedes"] == "d3f:precedes" and props["hardens"] == "d3f:hardens"
    assert cad["meta"]["d3fend_version"] == "9.9.9"


def test_attack_flow_is_deterministic_and_linked(c):
    a = render(SPEC, c, ["attack_flow"], timestamp=TS)["attack_flow"]
    b = render(SPEC, c, ["attack_flow"], timestamp=TS)["attack_flow"]
    assert a == b
    flow = next(o for o in a["objects"] if o["type"] == "attack-flow")
    actions = {o["id"]: o for o in a["objects"] if o["type"] == "attack-action"}
    assert len(flow["start_refs"]) == 1
    first = actions[flow["start_refs"][0]]
    assert first["technique_id"] == "T1566.002" and first["tactic_id"] == "TA0001"
    assert first["technique_ref"].startswith("attack-pattern--")
    assert any(o["type"] == "attack-asset" and o["name"] == "Mailbox" for o in a["objects"])


def test_attack_flow_validator_catches_errors(c):
    flow = render(SPEC, c, ["attack_flow"], timestamp=TS)["attack_flow"]
    broken = json.loads(json.dumps(flow))
    broken["objects"] = [o for o in broken["objects"] if o["type"] != "extension-definition"]
    action = next(o for o in broken["objects"] if o["type"] == "attack-action")
    action["effect_refs"] = ["attack-action--00000000-0000-4000-8000-000000000000"]
    del action["name"]
    errors = validate_attack_flow(broken)
    assert any("extension-definition" in e for e in errors)
    assert any("undefined" in e for e in errors)
    assert any("'name' is a required property" in e for e in errors)


def test_auto_countermeasures_without_mappings_warns(c_no_mappings):
    out = render(SPEC, c_no_mappings, ["mermaid"])
    assert any("not loaded" in w for w in out["warnings"]) and not out["countermeasure_links"]


GAP_SPEC = {
    "title": "Steps D3FEND does not cover",
    "steps": [
        {"id": "s1", "technique": "T1539"},
        {"id": "s2", "technique": "T1684", "after": ["s1"]},
        {"id": "s3", "technique": "T0001", "after": ["s2"]},
        {"id": "s4", "technique": "F1005.006", "after": ["s3"]},
    ],
    "countermeasures": "auto",
}


def test_render_reports_why_steps_have_no_countermeasures(c):
    out = render(GAP_SPEC, c, timestamp=TS)
    gaps = out["steps_without_countermeasures"]
    assert [(g["step"], g["technique"], g["gap_reason"]) for g in gaps] == [
        ("s2", "T1684", "predates"), ("s3", "T0001", "no_mapping"), ("s4", "F1005.006", "f3_native")]
    assert any("predates" in n for n in gaps[0]["notes"])
    # The diagrams carry the reason on the step, so a missing countermeasure never reads as an oversight.
    nodes = {n["data"]["label"].split()[0]: n["data"] for n in out["cad"]["nodes"] if n["type"] == "attack-node"}
    assert ["d3fend_countermeasures", "no D3FEND mapping yet: the loaded D3FEND release (9.9.9) predates it"] in \
        nodes["T1684"]["user_properties"]
    assert ["d3fend_countermeasures", "no D3FEND mapping for this technique"] in nodes["T0001"]["user_properties"]
    assert not any(p[0] == "d3fend_countermeasures" for p in nodes["T1539"]["user_properties"])
    assert not validate_cad(out["cad"])
    mmd = out["mermaid"]
    assert "[no D3FEND mapping: F3-native technique]" in mmd and "[no D3FEND mapping for this technique]" in mmd
    entries = {t["techniqueID"]: t for t in out["navigator"]["enterprise-attack"]["techniques"]}
    assert {"name": "d3fend", "value": "no D3FEND mapping yet: the loaded D3FEND release (9.9.9) predates it"} in \
        entries["T1684"]["metadata"]
    assert not any(m["name"] == "d3fend" for m in entries["T1539"]["metadata"])
    ics = {t["techniqueID"]: t for t in out["navigator"]["ics-attack"]["techniques"]}
    assert {"name": "d3fend", "value": "no D3FEND mapping for this technique"} in ics["T0001"]["metadata"]
    f3 = {t["techniqueID"]: t for t in out["navigator"]["f3-financial"]["techniques"]}
    assert {"name": "d3fend", "value": "no D3FEND mapping: F3-native technique"} in f3["F1005.006"]["metadata"]


def test_render_reports_steps_with_none_in_the_requested_tactics(c):
    spec = {**GAP_SPEC, "steps": GAP_SPEC["steps"][:1], "d3fend_tactics": ["Detect"]}
    gaps = render(spec, c, ["mermaid"], timestamp=TS)["steps_without_countermeasures"]
    assert [(g["step"], g["gap_reason"]) for g in gaps] == [("s1", "none_in_tactic")]
    assert "2 countermeasures exist" in gaps[0]["notes"][0] and "Detect" in gaps[0]["notes"][0]


def test_render_never_calls_unavailable_countermeasures_a_gap(c_no_mappings):
    out = render(GAP_SPEC, c_no_mappings, timestamp=TS)
    gaps = out["steps_without_countermeasures"]
    assert [g["gap_reason"] for g in gaps] == ["unavailable"] * 4
    assert any("not loaded" in w for w in out["warnings"])
    label = "D3FEND countermeasures unavailable: the D3FEND data is not loaded"
    assert out["mermaid"].count(f"[{label}]") == 4 and "no D3FEND mapping" not in out["mermaid"]
    for node in out["cad"]["nodes"]:
        assert ["d3fend_countermeasures", label] in node["data"]["user_properties"]
    assert not validate_cad(out["cad"])
    entries = out["navigator"]["enterprise-attack"]["techniques"]
    assert all({"name": "d3fend", "value": label} in t["metadata"] for t in entries if t["techniqueID"] != "T1566")


def test_steps_without_countermeasures_only_when_picked_automatically(c):
    assert "steps_without_countermeasures" not in render({**GAP_SPEC, "countermeasures": "none"}, c, ["mermaid"])
    explicit = {**GAP_SPEC, "countermeasures": [{"id": "D3-CH", "targets": ["s1"]}]}
    assert "steps_without_countermeasures" not in render(explicit, c, ["mermaid"])
    assert render(SPEC, c, ["mermaid"])["steps_without_countermeasures"] == [
        {"step": "s4", "technique": "F1005.006", "gap_reason": "f3_native",
         "notes": ["F3-native technique: D3FEND publishes no mappings for F3, and F3 has not published mitigations yet."]}]


def test_explicit_unmapped_countermeasure_is_an_analyst_assertion(c):
    spec = {**SPEC, "countermeasures": [{"id": "D3-UA", "targets": ["s2"]}]}
    out = render(spec, c, ["cad"], timestamp=TS)
    link = out["countermeasure_links"][0]
    assert link["provenance"] == "analyst"
    assert any("analyst assertion" in w for w in out["warnings"])
    assert any("analyst assertion" in e["data"]["label"] for e in out["cad"]["edges"])


@pytest.mark.parametrize("steps,message", [
    ([{"id": "a", "technique": "T1539"}, {"id": "a", "technique": "T1539"}], "duplicate"),
    ([{"id": "a", "technique": "T1539", "after": ["zz"]}], "unknown predecessor"),
    ([{"id": "a", "technique": "T1539", "after": ["b"]}, {"id": "b", "technique": "T1539", "after": ["a"]}], "cycle"),
])
def test_spec_validation(c, steps, message):
    with pytest.raises(ValidationError) as err:
        resolve_scenario({"title": "x", "steps": steps}, c)
    assert message in str(err.value)


def test_spec_rejects_unknown_and_non_technique_ids(c):
    with pytest.raises(NotFound):
        resolve_scenario({"title": "x", "steps": [{"id": "a", "technique": "T9999"}]}, c)
    with pytest.raises(NotFound, match="not a technique"):
        resolve_scenario({"title": "x", "steps": [{"id": "a", "technique": "G0016"}]}, c)


def test_navigator_layer_shapes(c):
    out = navigator_layers(c, ["T1566.002", "T1539", "F1005.006", "AML.T0051", "nope"], name="t")
    ent = out["layers"]["enterprise-attack"]
    entries = {t["techniqueID"]: t for t in ent["techniques"]}
    assert entries["T1566"]["showSubtechniques"] is True and "score" not in entries["T1566"]
    assert entries["T1566.002"]["score"] == 1
    assert ent["versions"]["attack"] == "20" and ent["versions"]["layer"] == "4.5"
    f3 = out["layers"]["f3-financial"]
    # The test build loads F3 from a local file, which a browser cannot fetch, so the layer falls back.
    assert f3["customDataURL"] == F3_DATA_URL and f3["filters"] == {"platforms": ["F3"]}
    assert any("customDataURL" in w for w in out["warnings"])
    assert any("AML.T0051" in w for w in out["warnings"]) and any("nope" in w for w in out["warnings"])


def test_f3_layer_loads_the_f3_file_the_database_was_built_from():
    pinned = ("https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/main/"
              "public/f3-stix-v1.2.json")
    assert f3_data_url(pinned) == (pinned, None)
    for unreachable in ("C:/data/f3.json", "/tmp/f3.json", "http://mirror.example/f3.json", None):
        url, note = f3_data_url(unreachable)
        assert url == F3_DATA_URL and "customDataURL" in note


def test_cad_defaults_match_what_d3fend_cad_writes(c, monkeypatch, tmp_path):
    monkeypatch.setenv("COUNTERMAP_CAD_CALIBRATION", str(tmp_path / "no-calibration.json"))
    cad = render(SPEC, c, ["cad"], timestamp=TS)["cad"]
    assert {(e["sourceHandle"], e["targetHandle"]) for e in cad["edges"]} == {("source", "target")}
    assert {e["markerEnd"]["type"] for e in cad["edges"]} == {"arrowclosed"}
    assert cad["meta"]["cad_schema_version"] == 1
    assert {n["data"]["sequence"] for n in cad["nodes"] if n["type"] != "attack-node"} == {"0"}


# Approximate sizes D3FEND CAD gives these nodes once it lays out their text and property
# tables (measured in CAD 0.26.1). The layout has to leave room for them.
CAD_DRAWN_SIZE = {"attack-node": (500, 300), "countermeasure-node": (500, 260), "artifact-node": (220, 120)}


def test_cad_layout_leaves_room_for_cad_sized_nodes(c):
    cad = render(SPEC, c, ["cad"], timestamp=TS)["cad"]
    boxes = [(n["id"], n["position"]["x"], n["position"]["y"], *CAD_DRAWN_SIZE[n["type"]]) for n in cad["nodes"]]
    overlaps = [(a[0], b[0]) for i, a in enumerate(boxes) for b in boxes[i + 1:]
                if a[1] < b[1] + b[3] and b[1] < a[1] + a[3] and a[2] < b[2] + b[4] and b[2] < a[2] + a[4]]
    assert overlaps == []


def test_cad_names_only_d3fend_classes_the_ontology_has(c):
    spec = {"title": "t", "countermeasures": "none",
            "steps": [{"id": "s1", "technique": "T1684"}, {"id": "s2", "technique": "T1539", "after": ["s1"]}]}
    out = render(spec, c, ["cad"], timestamp=TS)
    nodes = {n["data"]["label"].split()[0]: n["data"] for n in out["cad"]["nodes"]}
    assert "d3f_class" not in nodes["T1684"]
    assert ["d3fend_class", "none: not in the loaded D3FEND ontology (9.9.9)"] in nodes["T1684"]["user_properties"]
    assert nodes["T1539"]["d3f_class"] == "d3f:T1539"
    assert any("without a D3FEND class: T1684" in w for w in out["warnings"])


def test_cad_calibration_round_trip(c):
    exported = {"meta": {"cad_schema_version": 3, "d3fend_version": "1.6.0"},
                "edges": [{"sourceHandle": "right", "targetHandle": "left", "markerEnd": {"type": "arrow"}}] * 2}
    cal = calibrate_from_export(exported)
    assert cal["source_handle"] == "right" and cal["cad_schema_version"] == 3 and cal["calibrated"]
    cad = render_cad(resolve_scenario(SPEC, c), published=TS, calibration=cal)
    assert cad["meta"]["cad_schema_version"] == 3
    assert {e["sourceHandle"] for e in cad["edges"]} == {"right"}
    assert not validate_cad(cad)


def test_diff_snapshots(tmp_path):
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    build(old, write_fixtures(tmp_path / "o"), tmp_path / "cache", log=lambda m: None)
    revoked = attack_bundle(version="20.1", rename={"T1539": "Steal Web Session Cookies"},
                            extra_objects=[technique("T1700", "New Technique", ["stealth"])])
    for o in revoked["objects"]:
        if o.get("name") == "Social Engineering":
            o["x_mitre_deprecated"] = True
    build(new, write_fixtures(tmp_path / "n", attack=revoked), tmp_path / "cache", log=lambda m: None)
    d = diff_snapshots(old, new, framework="attack", kind="technique")
    assert d["old_versions"]["attack-enterprise"] == "20.0" and d["new_versions"]["attack-enterprise"] == "20.1"
    assert d["added"]["items"] == ["T1700 New Technique"]
    assert d["renamed"]["items"] == [{"id": "T1539", "old": "Steal Web Session Cookie", "new": "Steal Web Session Cookies"}]
    assert d["newly_deprecated"]["items"] == ["T1684 Social Engineering"]


def test_official_and_derived_countermeasure_nodes_are_separate(c):
    spec = {"title": "t", "steps": [{"id": "a", "technique": "T1566.002"},
                                    {"id": "b", "technique": "T1566", "after": ["a"]}],
            "countermeasures": "auto"}
    out = render(spec, c, ["cad", "mermaid"], timestamp=TS)
    labels = [n["data"]["label"] for n in out["cad"]["nodes"] if n["type"] == "countermeasure-node"]
    assert sorted(labels) == ["URL Analysis (D3-UA)", "URL Analysis (D3-UA) [derived]"]
    assert any(e["data"]["label"].endswith("(derived)") for e in out["cad"]["edges"])
    assert "[derived]" in out["mermaid"]


def test_attack_flow_ids_differ_for_different_flows_with_same_title(c):
    a = render({"title": "same", "steps": [{"id": "s1", "technique": "T1539"}]}, c, ["attack_flow"], timestamp=TS)
    b = render({"title": "same", "steps": [{"id": "s1", "technique": "T1566.002"}]}, c, ["attack_flow"], timestamp=TS)
    ids_a = {o["id"] for o in a["attack_flow"]["objects"] if o["type"].startswith("attack-")}
    ids_b = {o["id"] for o in b["attack_flow"]["objects"] if o["type"].startswith("attack-")}
    assert not ids_a & ids_b


def test_mermaid_escapes_user_text(c):
    spec = {"title": "x\n%% injected", "steps": [
        {"id": "s1", "technique": "T1539", "name": 'evil "]:::x <img src=x onerror=alert(1)> & \r more'}]}
    mmd = render(spec, c, ["mermaid"])["mermaid"]
    assert "<img" not in mmd and '"]:::x' not in mmd and "\r" not in mmd
    assert "#lt;img" in mmd and "#amp;" in mmd
    assert mmd.splitlines()[1].startswith("  %%") and len([l for l in mmd.splitlines() if "injected" in l]) == 1


@pytest.mark.parametrize("cm_id,message", [("D3A-CA", "analytic-technique"), ("SessionCookie", "artifact"),
                                           ("Harden", "tactic")])
def test_explicit_countermeasures_must_be_countermeasures(c, cm_id, message):
    spec = {**SPEC, "countermeasures": [{"id": cm_id, "targets": ["s2"]}]}
    with pytest.raises(NotFound, match=message):
        resolve_scenario(spec, c)


def test_duplicate_predecessors_are_deduplicated(c):
    spec = {"title": "t", "steps": [{"id": "a", "technique": "T1566.002"},
                                    {"id": "b", "technique": "T1539", "after": ["a", "a"]}]}
    flow = render(spec, c, ["attack_flow"], timestamp=TS)["attack_flow"]
    first = next(o for o in flow["objects"] if o["type"] == "attack-action" and o["technique_id"] == "T1566.002")
    assert len(first["effect_refs"]) == 1
