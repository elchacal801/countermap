"""Rule coverage: which in-scope techniques a ruleset's ATT&CK IDs cover, and the gaps ranked by group use."""

import json

import pytest

from countermap.query import NotFound

RULES = ["T1059.001", "T1003", "T1656"]  # T1656 is revoked in the fixtures, replaced by T1684.001


def ids(items):
    return [t["id"] for t in items]


def test_statuses_and_totals(c_detect):
    out = c_detect.rule_coverage(RULES)
    assert out["totals"] == {"in_scope": 14, "covered": 3, "partial": 3, "uncovered": 8}
    assert ids(out["covered"]) == ["T1003", "T1059.001", "T1684.001"]
    assert any("T1656 is revoked" in w and "T1684.001" in w for w in out["warnings"])
    status = {t["id"]: t for t in out["gaps"]}
    assert {k for k, v in status.items() if v["status"] == "partial"} == {"T1003.001", "T1059", "T1684"}
    # A sub-technique whose parent is in the list: a parent-level rule may catch it generally.
    assert status["T1003.001"]["reason"] == "covered via parent T1003"
    # A parent with some, but not all, of its sub-techniques covered.
    assert status["T1059"]["reason"] == "1 of 2 sub-techniques covered (T1059.001)"
    # A parent whose sub-techniques are all covered is still not covered itself.
    assert status["T1684"]["reason"] == "all 1 sub-techniques covered (T1684.001), but not T1684 itself"
    assert status["T1566"]["status"] == "uncovered" and "reason" not in status["T1566"]
    assert out["by_tactic"]["Execution"] == {"covered": 1, "partial": 1, "uncovered": 1}
    assert out["by_tactic"]["Stealth"] == {"covered": 1, "partial": 1, "uncovered": 2}
    assert "not prevalence in the wild" in out["basis"] and "computed by Countermap" in out["basis"]
    assert "through software they use (the latter derived by Countermap)" in out["basis"]
    assert "through software" in out["counting"] and "ranking uses the total" in out["counting"]


def test_gaps_are_ranked_by_group_use_with_software(c_detect):
    out = c_detect.rule_coverage(RULES)
    # Uncovered first, by groups (direct or through their software), then campaigns, then ID; then partial ones.
    assert ids(out["gaps"]) == ["T1105", "T1070", "T1566.002", "T1539", "T1027", "T1059.004", "T1538", "T1566",
                                "T1003.001", "T1059", "T1684"]
    gaps = {t["id"]: t for t in out["gaps"]}
    assert gaps["T1105"]["groups"] == {"count": 2, "direct": 2,
                                       "examples": ["G0100 Sandcastle (direct)", "G0101 Driftwood (direct)"]}
    assert gaps["T1105"]["campaigns"] == 1
    # Driftwood reaches T1070 and T1059.004 only through its software, S0100 Pulley: a Countermap derivation.
    assert gaps["T1070"]["groups"] == {"count": 2, "direct": 1, "examples": [
        "G0100 Sandcastle (direct)", "G0101 Driftwood (derived: via software S0100)"]}
    assert gaps["T1059.004"]["groups"] == {"count": 1, "direct": 0,
                                           "examples": ["G0101 Driftwood (derived: via software S0100)"]}
    # APT29 reaches T1539 through S0001; campaign C0001 uses it directly.
    assert gaps["T1539"]["groups"]["examples"] == ["G0016 APT29 (derived: via software S0001)"]
    assert gaps["T1539"]["campaigns"] == 1


def test_entries_carry_tactics_detection_strategies_and_data_components(c_detect):
    gaps = {t["id"]: t for t in c_detect.rule_coverage(RULES)["gaps"]}
    t1105 = gaps["T1105"]
    assert t1105["name"] == "Ingress Tool Transfer" and t1105["tactics"] == ["Command and Control"]
    assert t1105["status"] == "uncovered"
    assert t1105["detection_strategies"] == ["DET0102"]
    assert t1105["data_components"] == ["DC0082 Network Connection Creation"]
    assert gaps["T1003.001"]["data_components"] == ["DC0035 Process Access"]
    assert gaps["T1070"]["detection_strategies"] == [] and gaps["T1070"]["data_components"] == []


def test_scope_actors(c_detect):
    one = c_detect.rule_coverage(RULES, scope_actors=["G0101"])
    assert one["scope"]["actors"] == ["G0101 Driftwood"] and one["totals"]["in_scope"] == 4
    assert ids(one["gaps"]) == ["T1105", "T1070", "T1059.004", "T1003.001"]
    two = c_detect.rule_coverage(RULES, scope_actors=["G0100", "Driftwood"])
    assert ids(two["gaps"]) == ["T1105", "T1070", "T1027", "T1059.004", "T1538", "T1003.001"]
    assert ids(two["covered"]) == ["T1059.001"]
    gaps = {t["id"]: t for t in two["gaps"]}
    assert gaps["T1070"]["scope_actors"] == {"count": 2, "items": [
        "G0100 Sandcastle (direct)", "G0101 Driftwood (derived: via software S0100)"]}
    assert gaps["T1027"]["scope_actors"] == {"count": 1, "items": ["G0100 Sandcastle (direct)"]}
    # Repeated scope actors and tactics are taken once.
    again = c_detect.rule_coverage(RULES, scope_actors=["G0101"] * 60, tactics=["execution"] * 60)
    assert again["scope"]["actors"] == ["G0101 Driftwood"] and again["scope"]["tactics"] == ["Execution"]


def test_single_scope_actor_ties_break_by_overall_group_count(c_detect):
    gaps = c_detect.rule_coverage(RULES, scope_actors=["G0101"])["gaps"]
    by_id = {t["id"]: t for t in gaps}
    # Driftwood uses all three uncovered techniques, so each ties on scope actors (1).
    assert {by_id[i]["scope_actors"]["count"] for i in ("T1105", "T1070", "T1059.004")} == {1}
    # T1070 and T1059.004 also tie on campaigns (0); the overall group count (2 against 1) puts T1070 first.
    assert by_id["T1070"]["campaigns"] == by_id["T1059.004"]["campaigns"] == 0
    assert by_id["T1070"]["groups"]["count"] == 2 and by_id["T1059.004"]["groups"]["count"] == 1
    assert ids(gaps)[:3] == ["T1105", "T1070", "T1059.004"]
    assert "then all groups" in c_detect.rule_coverage(RULES)["counting"]


def test_platform_and_tactic_filters(c_detect):
    linux = c_detect.rule_coverage(RULES, platform="linux")
    assert linux["scope"]["platform"] == "Linux" and linux["totals"]["in_scope"] == 4
    assert ids(linux["covered"]) == ["T1003"] and ids(linux["gaps"]) == ["T1105", "T1059.004", "T1059"]
    assert linux["outside_scope"] == ["T1059.001", "T1684.001"]
    execution = c_detect.rule_coverage(RULES, tactics=["execution"])
    assert execution["totals"] == {"in_scope": 3, "covered": 1, "partial": 1, "uncovered": 1}
    assert c_detect.rule_coverage(RULES, tactics=["TA0002"])["totals"] == execution["totals"]
    assert c_detect.rule_coverage(RULES, tactics=["Execution", "Discovery"])["totals"]["in_scope"] == 4
    with pytest.raises(NotFound, match="unknown tactic"):
        c_detect.rule_coverage(RULES, tactics=["Exfiltrate"])
    with pytest.raises(NotFound, match="unknown domain"):
        c_detect.rule_coverage(RULES, domain="enterprise")


def test_unresolvable_rule_ids_are_reported(c_detect):
    out = c_detect.rule_coverage(["T1059.001", "T9999", "G0016", "T1586.004"])
    assert out["not_found"] == ["T9999", "G0016", "T1586.004"]
    assert out["rules"] == {"listed": 4, "resolved": 1, "in_scope": 1}


def test_gap_list_is_capped(c_detect):
    out = c_detect.rule_coverage(RULES, limit=2)
    assert ids(out["gaps"]) == ["T1105", "T1070"] and out["totals"]["uncovered"] == 8
    assert any("gaps" in n and "2 of 11" in n for n in out["notes"])


def test_rule_coverage_layer(c_detect):
    out = c_detect.rule_coverage(RULES, layer=True)
    layer = out["navigator"]["layers"]["enterprise-attack"]
    entries = {t["techniqueID"]: t for t in layer["techniques"]}
    assert {k: entries[k]["score"] for k in ("T1059.001", "T1059", "T1003.001", "T1105", "T1566")} == {
        "T1059.001": 2, "T1059": 1, "T1003.001": 1, "T1105": 0, "T1566": 0}
    assert "2 groups use it" in entries["T1105"]["comment"]
    assert "1 directly, 1 only through their software" in entries["T1070"]["comment"]
    assert "1 group uses it" in entries["T1059.001"]["comment"]
    assert "covered via parent T1003" in entries["T1003.001"]["comment"]
    assert [i["label"] for i in layer["legendItems"]] == ["covered (2)", "partial (1)", "uncovered (0)"]
    assert "navigator" not in c_detect.rule_coverage(RULES)


@pytest.fixture()
def detect_server(detect_db, monkeypatch):
    monkeypatch.setenv("COUNTERMAP_DB", str(detect_db))
    from countermap import server as srv

    srv._state.clear()
    return srv.server


def test_rule_coverage_tool(detect_server):
    import asyncio

    from mcp import Client

    async def run(args):
        async with Client(detect_server) as client:
            return json.loads((await client.call_tool("rule_coverage", args)).content[0].text)

    out = asyncio.run(run({"techniques": RULES, "scope_actors": ["G0101"]}))
    assert out["totals"]["in_scope"] == 4
    assert "error" in asyncio.run(run({"techniques": RULES, "tactics": ["Nope"]}))
    # One ID per rule: duplicates must not push a distinct ID past the cap (the reviewer's repro).
    dup = asyncio.run(run({"techniques": ["T1059.001"] * 2000 + ["T1003.001"], "limit": 300}))
    assert "T1003.001" in ids(dup["covered"]) and dup["rules"]["listed"] == 2


def test_duplicate_rule_ids_are_taken_once_and_cuts_are_noted(c_detect):
    out = c_detect.rule_coverage(["T1059.001"] * 2000 + ["t1003.001"])
    assert ids(out["covered"]) == ["T1003.001", "T1059.001"] and out["rules"]["listed"] == 2
    assert any("2 distinct" in n and "2001" in n for n in out["notes"])
    many = c_detect.rule_coverage([f"T{i}" for i in range(2000, 4001)])
    assert any("read the first 2000 of 2001" in n for n in many["notes"])


def test_broad_rule_layers_are_left_to_the_cli(c_detect, detect_server, monkeypatch):
    out = c_detect.rule_coverage(RULES, layer=True, max_layer_techniques=5)
    assert "navigator" not in out
    assert any("countermap rules-coverage" in n and "--layer FILE" in n for n in out["notes"])
    assert "navigator" in c_detect.rule_coverage(RULES, layer=True, max_layer_techniques=14)


SIGMA_RULE = """title: Suspicious PowerShell
id: 11111111-1111-4111-8111-111111111111
tags:
  - attack.execution
  - attack.t1059.001
  - ATTACK.T1105
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
"""

SIGMA_MULTI = """title: Collection
action: global
tags:
  - attack.t1003
---
title: Second
tags: [attack.t1027, attack.T1566.002x, attack.g0016, attack.s0001, notattack.t1070]
"""


def write_sigma(root):
    (root / "nested").mkdir(parents=True)
    (root / "a.yml").write_text(SIGMA_RULE, encoding="utf-8")
    (root / "nested" / "b.yaml").write_text(SIGMA_MULTI, encoding="utf-8")
    (root / "broken.yml").write_text("title: [unclosed\ntags: : :\n", encoding="utf-8")
    # A Python object tag that would call a function under an unsafe loader; safe_load must refuse it.
    (root / "unsafe.yml").write_text('!!python/object/apply:builtins.exit [3]\n', encoding="utf-8")
    (root / "list.yml").write_text("- just\n- a list\n", encoding="utf-8")
    (root / "notes.txt").write_text("tags: [attack.t1538]", encoding="utf-8")


def test_sigma_tags_are_collected_without_executing_anything(tmp_path):
    from countermap.cli import sigma_techniques

    write_sigma(tmp_path)
    techniques, stats = sigma_techniques(tmp_path)
    assert techniques == ["T1003", "T1027", "T1059.001", "T1105"]
    # Five YAML files: two fail to parse (skipped), one parses to a list (not a rule), two hold three rules.
    reasons = stats.pop("skipped_reasons")
    assert stats == {"files": 5, "skipped": 2, "rules": 3, "rules_with_technique_tags": 3, "links_not_followed": 0,
                     "unreadable_directories": 0}
    assert sum(reasons.values()) == 2 and reasons.get("ConstructorError") == 1


def test_sigma_reader_survives_hostile_files(tmp_path):
    import sys

    from countermap.cli import sigma_techniques

    (tmp_path / "ok.yml").write_text("title: ok\ntags: [attack.t1059]\n", encoding="utf-8")
    (tmp_path / "baddate.yml").write_text("title: bad\ndate: 2023-02-30\ntags: [attack.t1003]\n", encoding="utf-8")
    (tmp_path / "bigint.yml").write_text("tags: [attack.t1027]\nx: " + "9" * 100_000 + "\n", encoding="utf-8")
    (tmp_path / "deep.yml").write_text("tags: [attack.t1105]\nx: " + "[" * 20_000 + "]" * 20_000 + "\n",
                                       encoding="utf-8")
    (tmp_path / "huge.yml").write_text("title: huge\ntags: [attack.t1566]\n#" + "x" * (1024 * 1024) + "\n",
                                       encoding="utf-8")
    techniques, stats = sigma_techniques(tmp_path)
    # Interpreters with an integer-string limit (3.10.7 and later) refuse the 100,000-digit integer.
    limited = hasattr(sys, "get_int_max_str_digits")
    assert techniques == (["T1059"] if limited else ["T1027", "T1059"])
    assert stats["files"] == 5 and stats["skipped"] == (4 if limited else 3)
    # The deep file is caught by the nesting pre-scan, before the parser spends a minute recursing.
    assert stats["skipped_reasons"] == {"ValueError": 2 if limited else 1, "nesting too deep": 1, "over 1 MiB": 1}


def test_sigma_nesting_prescan(tmp_path):
    import time

    from countermap.cli import SIGMA_MAX_NESTING, _nesting_depth, sigma_techniques

    assert SIGMA_MAX_NESTING == 100
    assert _nesting_depth("a: [1, {b: [2]}]") == 3
    # Brackets inside quoted strings do not count; an apostrophe inside a word does not open a string.
    assert _nesting_depth("x: '" + "[" * 500 + "'\ny: \"" + "{" * 500 + "\"\nz: it's [1]\n") == 1
    assert _nesting_depth("x: 'it''s " + "[" * 500 + "'\n") == 0
    assert _nesting_depth("# " + "[" * 500 + "\nx: [1]\n") == 1  # a comment
    (tmp_path / "ok.yml").write_text("title: ok\ntags: [attack.t1059]\nx: '" + "[" * 300 + "'\n", encoding="utf-8")
    (tmp_path / "just_over.yml").write_text("tags: [attack.t1003]\nx: " + "[" * 101 + "]" * 101 + "\n",
                                            encoding="utf-8")
    (tmp_path / "deep.yml").write_text("tags: [attack.t1105]\nx: " + "[" * 200_000 + "]" * 200_000 + "\n",
                                       encoding="utf-8")
    start = time.time()
    techniques, stats = sigma_techniques(tmp_path)
    assert time.time() - start < 10
    assert techniques == ["T1059"] and stats["skipped_reasons"] == {"nesting too deep": 2}


def test_sigma_reader_does_not_follow_directory_links(tmp_path):
    import os
    import subprocess

    from countermap.cli import sigma_techniques

    loop = tmp_path / "loop"
    (loop / "sub").mkdir(parents=True)
    (loop / "r.yml").write_text("tags: [attack.t1059]\n", encoding="utf-8")
    made = 0
    for name in ("back1", "back2"):
        link = loop / "sub" / name
        if os.name == "nt":  # a junction needs no privileges on Windows
            made += subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(loop)],
                                   capture_output=True).returncode == 0
        else:
            try:
                os.symlink(loop, link, target_is_directory=True)
                made += 1
            except OSError:
                pass
    if made != 2:
        pytest.skip("cannot create directory links here")
    techniques, stats = sigma_techniques(loop)
    assert techniques == ["T1059"] and stats["files"] == 1 and stats["links_not_followed"] == 2


def test_cli_rules_coverage(detect_db, capsys, tmp_path):
    from countermap import cli

    layer = tmp_path / "rules.json"
    assert cli.main(["--db", str(detect_db), "rules-coverage", "--technique", "T1059.001", "--technique", "T1003",
                     "--technique", "T1656", "--layer", str(layer)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["totals"]["covered"] == 3 and "navigator" not in out
    assert json.loads(layer.read_text(encoding="utf-8"))["domain"] == "enterprise-attack"

    sigma = tmp_path / "sigma"
    write_sigma(sigma)
    assert cli.main(["--db", str(detect_db), "rules-coverage", "--sigma", str(sigma), "--actor", "G0100",
                     "--actor", "G0101", "--platform", "Windows", "--tactic", "Command and Control"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["sigma"]["skipped"] == 2 and out["sigma"]["techniques"] == 4
    assert out["scope"]["actors"] == ["G0100 Sandcastle", "G0101 Driftwood"]
    assert ids(out["covered"]) == ["T1105"]
    assert cli.main(["--db", str(detect_db), "rules-coverage", "--sigma", str(tmp_path / "missing")]) == 2
