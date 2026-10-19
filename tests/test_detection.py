"""ATT&CK's detection model: analytic tunables, campaign dates, detection detail, lookups of
detection objects and the telemetry-coverage query."""

import json
import sqlite3

import pytest

from countermap.query import NotFound

from conftest import LONG_ANALYTIC_DESCRIPTION


def extra(db, node_id):
    conn = sqlite3.connect(db)
    value = conn.execute("SELECT extra FROM nodes WHERE id = ?", (node_id,)).fetchone()[0]
    conn.close()
    return json.loads(value or "{}")


# -- A. ingestion ---------------------------------------------------------------

def test_analytic_mutable_elements_round_trip(detect_db):
    assert extra(detect_db, "attack:AN0101")["mutable_elements"] == [
        {"field": "ParentProcessAllowList", "description": "Parents allowed to start PowerShell."},
        {"field": "TimeWindow", "description": "Correlation window in seconds."},
    ]
    # An analytic MITRE gives no tunables gets no key, rather than an empty claim.
    assert "mutable_elements" not in extra(detect_db, "attack:AN0104")


def test_campaign_dates_and_citations_round_trip(detect_db):
    assert {k: v for k, v in extra(detect_db, "attack:C0001").items() if "seen" in k} == {
        "first_seen": "2023-02-01T05:00:00.000Z",
        "last_seen": "2024-06-01T04:00:00.000Z",
        "first_seen_citation": "(Citation: Test Report 2023)",
        "last_seen_citation": "(Citation: Test Follow-up 2024)",
    }
    assert not any("seen" in k for k in extra(detect_db, "attack:C0100"))


def test_lookup_shows_campaign_dates(c_detect):
    out = c_detect.lookup("C0001")
    assert out["first_seen"] == "2023-02-01T05:00:00.000Z" and out["last_seen"] == "2024-06-01T04:00:00.000Z"
    assert out["first_seen_citation"] == "(Citation: Test Report 2023)"


# -- B. detection detail --------------------------------------------------------

def test_detection_strategies_carry_analytic_descriptions_and_tunables(c_detect):
    (det,) = c_detect.detection_strategies("attack:T1059.001")
    assert det["id"] == "DET0100"
    by_id = {a["id"]: a for a in det["analytics"]}
    assert by_id["AN0100"]["description"] == LONG_ANALYTIC_DESCRIPTION
    assert by_id["AN0100"]["mutable_elements"] == [
        {"field": "ScriptBlockAllowList", "description": "Signed administrative scripts to ignore."}]
    # What it returned before is still there.
    assert by_id["AN0101"]["platforms"] == ["Windows"]
    assert by_id["AN0101"]["log_sources"] == [
        {"data_component": "DC0032 Process Creation", "name": "WinEventLog:Sysmon", "channel": "EventCode=1"}]
    assert "mutable_elements" not in next(a for a in c_detect.detection_strategies("attack:T1105")[0]["analytics"]
                                          if a["id"] == "AN0104")


def test_technique_context_carries_analytic_detail_under_its_limit(c_detect):
    ctx = c_detect.technique_context("T1059.001", limit=1)
    an = {a["id"]: a for a in ctx["detection_strategies"][0]["analytics"]}
    assert an["AN0101"]["description"] == "AN0101 detection logic."
    assert [m["field"] for m in an["AN0101"]["mutable_elements"]] == ["ParentProcessAllowList", "TimeWindow"]
    assert len(ctx["detection_strategies"]) == 1


def test_step_detections_list_each_strategy_analytics(c_detect):
    from countermap.emit import render

    spec = {"title": "t", "steps": [{"id": "s1", "technique": "T1059.001"}, {"id": "s2", "technique": "T1070",
                                                                          "after": ["s1"]}]}
    out = render(spec, c_detect, ["mermaid"])
    (det,) = out["step_detections"][0]["detection_strategies"]
    # The flattened fields are unchanged ...
    assert det["id"] == "DET0100" and det["name"] == "Detect suspicious PowerShell" and det["platforms"] == ["Windows"]
    assert {(ls["log_source"], ls["channel"]) for ls in det["log_sources"]} == {
        ("WinEventLog:Sysmon", "EventCode=1"), ("WinEventLog:PowerShell", "EventCode=4104")}
    # ... and each analytic is listed with its platforms, a short description and its tunable field names.
    by_id = {a["id"]: a for a in det["analytics"]}
    assert set(by_id) == {"AN0100", "AN0101"}
    assert set(by_id["AN0100"]) == {"id", "platforms", "description", "tunables"}
    long = by_id["AN0100"]["description"]
    assert len(long) <= 300 and long.endswith("…") and LONG_ANALYTIC_DESCRIPTION.startswith(long[:-1])
    assert by_id["AN0100"]["tunables"] == ["ScriptBlockAllowList"]
    assert by_id["AN0101"] == {"id": "AN0101", "platforms": ["Windows"], "description": "AN0101 detection logic.",
                               "tunables": ["ParentProcessAllowList", "TimeWindow"]}
    assert out["step_detections"][1]["detection_strategies"] == []


# -- C. telemetry coverage ------------------------------------------------------

def ids(out, cls):
    return [t["id"] for t in out["techniques"][cls]]


def test_telemetry_coverage_classifies_an_actors_techniques(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"], platform="Windows", actor="Sandcastle")
    assert out["target"]["kind"] == "actor" and out["target"]["actor"]["ext_id"] == "G0100"
    assert out["counts"] == {"covered": 1, "partial": 1, "blind": 2, "no_analytic_for_platform": 1,
                             "no_detection_strategy": 1}
    assert ids(out, "covered") == ["T1059.001"]
    assert ids(out, "partial") == ["T1003.001"]
    assert ids(out, "blind") == ["T1027", "T1105"]
    assert ids(out, "no_analytic_for_platform") == ["T1538"]
    assert ids(out, "no_detection_strategy") == ["T1070"]
    # Covered: the analytic whose log sources are all in the telemetry (AN0100 also needs PowerShell logs).
    (covered,) = out["techniques"]["covered"]
    assert covered["analytics"] == [{"id": "AN0101", "detection_strategy": "DET0100", "platforms": ["Windows"],
                                     "log_sources": ["WinEventLog:Sysmon EventCode=1 (DC0032)"]}]
    # Partial: what the analytic already uses, and what it is missing.
    (partial,) = out["techniques"]["partial"]
    assert partial["analytics"] == [{"id": "AN0102", "detection_strategy": "DET0101", "platforms": ["Windows"],
                                     "matched": ["WinEventLog:Sysmon EventCode=10 (DC0035)"],
                                     "missing": ["WinEventLog:Security EventCode=4663, 4656 (DC0035)"]}]
    blind = {t["id"]: t for t in out["techniques"]["blind"]}
    assert blind["T1105"]["missing"] == ["Network Traffic (DC0082)"]
    assert out["techniques"]["no_analytic_for_platform"][0]["analytic_platforms"] == ["IaaS"]
    assert out["data_components"]["DC0035"] == "Process Access"
    assert "computed by Countermap" in out["basis"] and "log-source references" in out["basis"]


def test_a_log_source_without_a_channel_matches_every_channel(c_detect):
    whole = c_detect.telemetry_coverage(log_sources=["winEventLog:SYSMON"], techniques=["T1003.001"],
                                        platform="windows")
    assert whole["counts"]["partial"] == 1
    # With a channel, only that channel is collected: EventCode=1 says nothing about EventCode=10.
    one = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon EventCode=1"],
                                      techniques=["T1059.001", "T1003.001"], platform="Windows")
    assert ids(one, "covered") == ["T1059.001"] and ids(one, "blind") == ["T1003.001"]


def test_event_code_lists_are_compared_as_sets(c_detect):
    def classes(sources):
        out = c_detect.telemetry_coverage(log_sources=sources, techniques=["T1003.001"], platform="Windows")
        return {k for k, v in out["counts"].items() if v}

    assert classes(["WinEventLog:Sysmon", "WinEventLog:Security EventCode=4663"]) == {"partial"}
    assert classes(["WinEventLog:Sysmon", "WinEventLog:Security EventCode=4663",
                    "WinEventLog:Security EventCode=4656"]) == {"covered"}
    assert classes(["WinEventLog:Sysmon", "WinEventLog:Security EventCode=4656,4663"]) == {"covered"}
    assert classes(["WinEventLog:Sysmon", "WinEventLog:Security"]) == {"covered"}


def test_log_source_names_with_spaces_and_none_channels(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["Network Traffic"], techniques=["T1105"], platform="Windows")
    assert ids(out, "covered") == ["T1105"]


def test_data_components_count_as_telemetry(c_detect):
    out = c_detect.telemetry_coverage(data_components=["DC0082", "Process Access"],
                                      techniques=["T1105", "T1003.001", "T1059.001"], platform="Windows")
    assert ids(out, "covered") == ["T1003.001", "T1105"] and ids(out, "blind") == ["T1059.001"]
    assert out["telemetry"]["data_components"] == ["DC0035 Process Access", "DC0082 Network Connection Creation"]


def test_platform_filter(c_detect):
    linux = c_detect.telemetry_coverage(log_sources=["auditd:SYSCALL"], platform="Linux",
                                        techniques=["T1105", "T1059.004", "T1059.001"])
    assert ids(linux, "covered") == ["T1059.004", "T1105"]
    assert ids(linux, "no_analytic_for_platform") == ["T1059.001"]
    # Without a platform every analytic counts, and a technique with analytics anywhere is never "no analytic".
    anywhere = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"], actor="G0100")
    assert anywhere["counts"]["no_analytic_for_platform"] == 0 and "T1538" in ids(anywhere, "blind")


def test_an_analytic_without_log_sources_is_never_covered(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon", "WinEventLog:Security", "Network Traffic",
                                                   "WinEventLog:PowerShell"], techniques=["T1027"])
    assert ids(out, "blind") == ["T1027"]
    assert out["techniques"]["blind"][0]["missing"] == []


def test_all_techniques_on_a_platform_is_the_default_target(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["AWS:CloudTrail ConsoleLogin"], platform="IaaS")
    assert out["target"] == {"kind": "all", "domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
                             "techniques": 1}
    assert ids(out, "covered") == ["T1538"]


def test_actor_software_techniques_are_labeled(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["auditd:SYSCALL"], platform="Linux", actor="Driftwood",
                                      include_software=True)
    entry = next(t for t in out["techniques"]["covered"] if t["id"] == "T1059.004")
    assert entry["via"] == "software S0100"
    assert "via" not in next(t for t in out["techniques"]["covered"] if t["id"] == "T1105")


def test_telemetry_coverage_input_errors_and_warnings(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon", "NoSuchLog:Thing"],
                                      data_components=["DC9999"], techniques=["T1059.001", "T9999"])
    assert any("NoSuchLog:Thing" in w for w in out["warnings"]) and any("DC9999" in w for w in out["warnings"])
    assert out["not_found"] == ["T9999"]
    with pytest.raises(NotFound, match="log_sources or data_components"):
        c_detect.telemetry_coverage(techniques=["T1059.001"])
    with pytest.raises(NotFound, match="not both"):
        c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"], techniques=["T1059.001"], actor="G0100")
    with pytest.raises(NotFound, match="unknown platform"):
        c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"], platform="Windoze")


def test_telemetry_coverage_lists_are_capped(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"], platform="Windows", actor="G0100", limit=1)
    assert len(out["techniques"]["blind"]) == 1 and out["counts"]["blind"] == 2
    assert any("blind" in n and "1 of 2" in n for n in out["notes"])


def test_telemetry_coverage_navigator_layer(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"], platform="Windows", actor="G0100",
                                      layer=True)
    layer = out["navigator"]["layers"]["enterprise-attack"]
    entries = {t["techniqueID"]: t for t in layer["techniques"]}
    assert {k: entries[k].get("score") for k in ("T1059.001", "T1003.001", "T1105", "T1027", "T1070", "T1538")} == {
        "T1059.001": 2, "T1003.001": 1, "T1105": 0, "T1027": 0, "T1070": None, "T1538": None}
    assert entries["T1070"]["comment"].startswith("no ATT&CK detection strategy")
    assert entries["T1059.001"]["comment"].startswith("covered")
    assert layer["gradient"]["minValue"] == 0 and layer["gradient"]["maxValue"] == 2
    assert [i["label"] for i in layer["legendItems"]] == ["covered (2)", "partial (1)", "blind (0)"]
    assert "navigator" not in c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"], actor="G0100")


@pytest.fixture()
def detect_server(detect_db, monkeypatch):
    monkeypatch.setenv("COUNTERMAP_DB", str(detect_db))
    from countermap import server as srv

    srv._state.clear()
    return srv.server


def call_tool(server, name, args):
    import asyncio

    from mcp import Client

    async def run():
        async with Client(server) as client:
            result = await client.call_tool(name, args)
            return json.loads(result.content[0].text)

    return asyncio.run(run())


def test_telemetry_coverage_tool(detect_server):
    out = call_tool(detect_server, "telemetry_coverage",
                    {"log_sources": ["WinEventLog:Sysmon"], "platform": "Windows", "actor": "G0100", "layer": True})
    assert out["counts"]["covered"] == 1 and "enterprise-attack" in out["navigator"]["layers"]
    assert "error" in call_tool(detect_server, "telemetry_coverage", {"techniques": ["T1059.001"]})


def test_cli_coverage(detect_db, capsys, tmp_path):
    from countermap import cli

    layer = tmp_path / "coverage.json"
    assert cli.main(["--db", str(detect_db), "coverage", "--log-source", "WinEventLog:Sysmon EventCode=1",
                     "--log-source", "WinEventLog:Sysmon EventCode=10", "--technique", "T1059.001",
                     "--technique", "T1003.001", "--platform", "Windows", "--layer", str(layer)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["counts"]["covered"] == 1 and out["counts"]["partial"] == 1
    assert "navigator" not in out
    written = json.loads(layer.read_text(encoding="utf-8"))
    assert written["domain"] == "enterprise-attack" and {t["techniqueID"] for t in written["techniques"]} >= {
        "T1059.001", "T1003.001"}
    assert cli.main(["--db", str(detect_db), "coverage", "--data-component", "DC0082", "--actor", "Driftwood"]) == 0
    assert json.loads(capsys.readouterr().out)["target"]["actor"]["ext_id"] == "G0101"
    assert cli.main(["--db", str(detect_db), "coverage", "--actor", "G0100"]) == 4


# -- review fixes: inputs, layers, domains ----------------------------------------

FILLER = [f"Filler:Source{i}" for i in range(119)]


def test_many_unknown_log_sources_do_not_hide_a_known_one(c_detect, detect_server):
    out = c_detect.telemetry_coverage(log_sources=FILLER + ["WinEventLog:Sysmon"], techniques=["T1059.001"])
    assert out["counts"]["covered"] == 1
    # One warning per unknown name for the first 20, then one line for the rest.
    unknown = [w for w in out["warnings"] if "log source" in w]
    assert len(unknown) == 21 and "99 more" in unknown[-1]
    # The reviewer's repro through MCP: the server's cap used to cut Sysmon off, silently.
    mcp = call_tool(detect_server, "telemetry_coverage",
                    {"log_sources": FILLER + ["WinEventLog:Sysmon"], "techniques": ["T1059.001"]})
    assert mcp["counts"]["covered"] == 1


def test_telemetry_inputs_are_deduplicated_before_capping_and_cuts_are_noted(c_detect, detect_server):
    dup = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"] * 500,
                                      techniques=["T1059.001"] * 400 + ["t1003.001"])
    assert dup["telemetry"]["log_sources"] == ["WinEventLog:Sysmon"] and dup["target"]["techniques"] == 2
    assert not any("first" in n for n in dup.get("notes", []))
    many = c_detect.telemetry_coverage(log_sources=[f"Filler:Source{i}" for i in range(400)] + ["WinEventLog:Sysmon"],
                                       data_components=[f"DC{i:04d}" for i in range(5000, 5301)],
                                       techniques=[f"T{i}" for i in range(2000, 2301)] + ["T1059.001"])
    notes = " | ".join(many["notes"])
    assert "log_sources: used the first 300 of 401" in notes
    assert "data_components: used the first 300 of 301" in notes
    assert "checked the first 300 of 302 techniques" in notes
    # The MCP wrapper de-duplicates first and caps above the query's caps, so the same notes come through.
    mcp = call_tool(detect_server, "telemetry_coverage",
                    {"log_sources": ["WinEventLog:Sysmon"] * 2000 + [f"Filler:Source{i}" for i in range(400)],
                     "techniques": ["T1059.001"]})
    assert mcp["counts"]["covered"] == 1 and "log_sources: used the first 300 of 401" in " | ".join(mcp["notes"])


def test_channels_that_match_no_analytic_are_warned(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon EventCode=3", "WinEventLog:Sysmon EventCode=10",
                                                   "WinEventLog:Security EventCode=4663"], techniques=["T1003.001"])
    hits = [w for w in out.get("warnings", []) if "no ATT&CK analytic uses" in w]
    assert len(hits) == 1 and "EventCode=3" in hits[0] and "EventCode=10" in hits[0]  # names the channels that exist


def test_a_data_component_name_in_log_sources_is_flagged(c_detect):
    out = c_detect.telemetry_coverage(log_sources=["Process Creation"], techniques=["T1059.001"])
    hits = [w for w in out["warnings"] if "Process Creation" in w]
    assert len(hits) == 1 and "data_components" in hits[0] and "DC0032" in hits[0]


def test_telemetry_coverage_domain(c_detect):
    default = c_detect.telemetry_coverage(log_sources=["IdP:SignIn"], techniques=["T0001", "T1539"])
    assert default["target"]["domains"] == ["enterprise-attack", "mobile-attack", "ics-attack"]
    assert ids(default, "covered") == ["T0001", "T1539"]
    ics = c_detect.telemetry_coverage(log_sources=["IdP:SignIn"], techniques=["T0001", "T1539"], domain="ics-attack")
    assert ics["target"] == {"kind": "techniques", "domains": ["ics-attack"], "techniques": 1}
    assert ids(ics, "covered") == ["T0001"] and ics["outside_domain"] == ["T1539"]
    everything = c_detect.telemetry_coverage(log_sources=["IdP:SignIn"], domain="ics-attack")
    assert everything["target"] == {"kind": "all", "domains": ["ics-attack"], "techniques": 1}
    actor = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"], actor="G0100", domain="mobile-attack")
    assert actor["target"]["techniques"] == 0 and len(actor["outside_domain"]) == 6
    with pytest.raises(NotFound, match="unknown domain"):
        c_detect.telemetry_coverage(log_sources=["IdP:SignIn"], domain="ics")


def test_cli_coverage_domain(detect_db, capsys):
    from countermap import cli

    assert cli.main(["--db", str(detect_db), "coverage", "--log-source", "IdP:SignIn", "--domain", "ics-attack"]) == 0
    assert json.loads(capsys.readouterr().out)["target"] == {"kind": "all", "domains": ["ics-attack"], "techniques": 1}


def test_broad_layers_are_left_to_the_cli(c_detect, detect_server, detect_db, monkeypatch, tmp_path, capsys):
    out = c_detect.telemetry_coverage(log_sources=["WinEventLog:Sysmon"], actor="G0100", layer=True,
                                      max_layer_techniques=2)
    assert "navigator" not in out
    assert any("countermap coverage" in n and "--layer FILE" in n for n in out["notes"])
    from countermap import cli
    from countermap import server as srv

    # About 120 techniques keeps a layer response near 75 KB, under Claude Code's default MCP output limit.
    assert srv.LAYER_MAX_TECHNIQUES == 120
    monkeypatch.setattr(srv, "LAYER_MAX_TECHNIQUES", 2)
    broad = call_tool(detect_server, "telemetry_coverage",
                      {"log_sources": ["WinEventLog:Sysmon"], "actor": "G0100", "layer": True})
    assert "navigator" not in broad and any("--layer FILE" in n for n in broad["notes"])
    small = call_tool(detect_server, "telemetry_coverage",
                      {"log_sources": ["WinEventLog:Sysmon"], "techniques": ["T1059.001"], "layer": True})
    assert "navigator" in small
    # The CLI is not limited.
    layer = tmp_path / "broad.json"
    assert cli.main(["--db", str(detect_db), "coverage", "--log-source", "WinEventLog:Sysmon", "--actor", "G0100",
                     "--layer", str(layer)]) == 0
    capsys.readouterr()
    assert len(json.loads(layer.read_text(encoding="utf-8"))["techniques"]) >= 6


# -- D. lookup of detection objects ---------------------------------------------

SECURITY_4663 = {"data_component": "DC0035 Process Access", "name": "WinEventLog:Security", "channel": "EventCode=4663, 4656"}
SYSMON_10 = {"data_component": "DC0035 Process Access", "name": "WinEventLog:Sysmon", "channel": "EventCode=10"}


def test_lookup_detection_strategy_shows_techniques_and_analytics(c_detect):
    out = c_detect.lookup("DET0101")
    assert out["relations"]["detects ->"]["items"] == ["attack:T1003.001 LSASS Memory"]
    assert out["analytics"] == [{"id": "AN0102", "platforms": ["Windows"], "log_sources": [SYSMON_10, SECURITY_4663]}]


def test_lookup_analytic_shows_strategy_technique_log_sources_and_tunables(c_detect):
    out = c_detect.lookup("AN0102")
    assert out["detection_strategies"] == [
        {"id": "DET0101", "name": "Detect LSASS access", "detects": ["T1003.001 LSASS Memory"]}]
    assert out["description"] == "AN0102 detection logic."
    assert out["log_sources"] == [SYSMON_10, SECURITY_4663]
    assert out["mutable_elements"] == [{"field": "GrantedAccessMask",
                                        "description": "Access masks treated as credential reads."}]


def test_lookup_data_component_shows_analytics_and_techniques(c_detect):
    out = c_detect.lookup("DC0032")
    assert out["analytics"]["count"] == 3
    assert out["analytics"]["items"][0] == {"id": "AN0100", "platforms": ["Windows"],
                                            "detection_strategy": "DET0100 Detect suspicious PowerShell"}
    assert out["techniques"]["count"] == 2
    assert out["techniques"]["items"] == ["T1059.001 PowerShell", "T1059.004 Unix Shell"]
    assert "detection strategies" in out["techniques"]["via"]
    capped = c_detect._detection_detail(c_detect._node("attack:DC0032"), limit=1)
    assert len(capped["analytics"]["items"]) == 1 and capped["analytics"]["count"] == 3
    assert capped["techniques"]["items"] == ["T1059.001 PowerShell"] and capped["techniques"]["count"] == 2
