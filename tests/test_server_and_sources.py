import asyncio
import json

import pytest

from countermap.sources import (
    ResolvedSource,
    compare_to_lock,
    read_lock,
    resolve_attack,
    url_override,
    write_lock,
)


def _call(server, name, args):
    from mcp import Client

    async def run():
        async with Client(server) as client:
            if name is None:
                return await client.list_tools()
            result = await client.call_tool(name, args)
            return json.loads(result.content[0].text)

    return asyncio.run(run())


@pytest.fixture()
def server(built, monkeypatch):
    monkeypatch.setenv("COUNTERMAP_DB", str(built))
    from countermap import server as srv

    srv._state.clear()
    return srv.server


def test_tools_are_listed_and_read_only(server):
    tools = _call(server, None, None).tools
    names = {t.name for t in tools}
    assert names == {"datasets", "search", "lookup", "technique_context", "countermeasures", "crosswalk",
                     "actor_techniques", "compare_actors", "coverage_gaps", "version_diff", "navigator_layer",
                     "render_scenario", "telemetry_coverage", "rule_coverage"}
    assert all(t.annotations.read_only_hint and not t.annotations.open_world_hint for t in tools)


def test_tool_calls(server):
    assert _call(server, "lookup", {"ref": "Cozy Bear"})["ext_id"] == "G0016"
    out = _call(server, "render_scenario", {"spec": {"title": "t", "steps": [{"id": "s1", "technique": "T1539"}]},
                                            "formats": ["cad", "mermaid"]})
    assert out["cad"]["nodes"] and out["mermaid"].startswith("flowchart")
    layer = _call(server, "navigator_layer", {"actor": "APT29"})
    assert layer["layers"]["enterprise-attack"]["name"] == "APT29 (G0016)"


def test_tool_errors_are_returned_not_raised(server, monkeypatch, tmp_path):
    assert "error" in _call(server, "lookup", {"ref": "T9999"})
    assert "error" in _call(server, "lookup", {"ref": "x" * 100_000})
    assert "error" in _call(server, "coverage_gaps", {"techniques": ["y" * 50_000]})["techniques"][0]
    assert "error" in _call(server, "render_scenario", {"spec": {"title": "t", "steps": []}})
    assert "error" in _call(server, "version_diff", {})


def test_missing_database_is_an_error_result(monkeypatch, tmp_path):
    monkeypatch.setenv("COUNTERMAP_DB", str(tmp_path / "nope.db"))
    from countermap import server as srv

    srv._state.clear()
    out = _call(srv.server, "lookup", {"ref": "T1539"})
    assert "Run `countermap build` first" in out["error"]


def test_lock_round_trip_and_compare(tmp_path):
    lock = tmp_path / "sources.lock.json"
    srcs = [ResolvedSource("f3", "1.2", "https://x/f3.json", sha256="a" * 64)]
    write_lock(lock, srcs)
    back = read_lock(lock)
    assert back[0].key == "f3" and back[0].sha256 == "a" * 64 and back[0].framework == "f3"
    assert compare_to_lock(back, [ResolvedSource("f3", "1.2", "https://x/f3.json")]) == []
    changes = compare_to_lock(back, [ResolvedSource("f3", "1.3", "https://x/f3.json")])
    assert changes[0]["change"] == "new-version" and changes[0]["latest"] == "1.3"


def test_resolve_attack_from_local_index_and_override(tmp_path, monkeypatch):
    index = {"collections": [
        {"name": "Enterprise ATT&CK", "versions": [{"version": "20.0", "url": "https://x/e-20.json"},
                                                    {"version": "19.2", "url": "https://x/e-19.json"}]},
        {"name": "Mobile ATT&CK", "versions": [{"version": "20.0", "url": "https://x/m-20.json"},
                                                {"version": "19.2", "url": "https://x/m-19.json"}]},
    ]}
    path = tmp_path / "index.json"
    path.write_text(json.dumps(index))
    monkeypatch.setenv("COUNTERMAP_URL_ATTACK_INDEX", str(path))
    monkeypatch.setenv("COUNTERMAP_URL_ATTACK_MOBILE", "/mirror/mobile.json")
    assert url_override("attack-mobile") == "/mirror/mobile.json"
    latest = {s.key: s for s in resolve_attack()}
    assert latest["attack-enterprise"].version == "20.0"
    assert latest["attack-mobile"].url == "/mirror/mobile.json"
    pinned = {s.key: s for s in resolve_attack("19.2") if s.key == "attack-enterprise"}
    assert pinned["attack-enterprise"].url == "https://x/e-19.json"


def test_cli_output_is_utf8_when_the_locale_is_not(built, monkeypatch):
    import io
    import sys

    from countermap import cli

    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    assert cli.main(["--db", str(built), "lookup", "T1539"]) == 0
    cli._print({"name": "Operation AkaiRyū"})
    text = raw.getvalue().decode("utf-8")
    assert "Steal Web Session Cookie" in text and "Operation AkaiRyū" in text


def test_help_describes_countermap_in_utf8_when_the_locale_is_not(monkeypatch):
    import io
    import sys

    from countermap import cli

    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    sys.stdout.flush()
    text = raw.getvalue().decode("utf-8")
    assert "Command-line interface." not in text
    assert "MITRE ATT&CK®" in text and "D3FEND" in text and "ATLAS" in text and "F3" in text
    assert "countermap build" in text and "countermap serve" in text


def test_check_updates_without_a_lock_file_says_how_to_get_one(tmp_path, monkeypatch, capsys):
    from countermap import cli

    def upstream(*args, **kwargs):
        raise AssertionError("check-updates reached upstream without a lock file to compare against")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_all", upstream)
    assert cli.main(["check-updates"]) == 2
    err = capsys.readouterr().err
    assert "no lock file at sources.lock.json" in err and "--lock PATH" in err and "countermap lock" in err
    assert cli.main(["check-updates", "--lock", str(tmp_path / "missing.lock.json")]) == 2
    assert "missing.lock.json" in capsys.readouterr().err


def test_check_updates_compares_the_lock_in_the_current_directory(tmp_path, monkeypatch, capsys):
    from countermap import cli

    write_lock(tmp_path / "sources.lock.json", [ResolvedSource("f3", "1.2", "https://x/f3.json", sha256="a" * 64)])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_all", lambda *a, **k: [ResolvedSource("f3", "1.3", "https://x/f3.json")])
    assert cli.main(["check-updates"]) == 10
    assert json.loads(capsys.readouterr().out)["changes"][0]["latest"] == "1.3"


def _fake_read_text(pages):
    from countermap.sources import FetchError

    def read_text(ref, timeout=60):
        if ref not in pages:
            raise FetchError(f"could not read {ref}")
        return pages[ref]

    return read_text


def test_resolve_d3fend_pins_the_versioned_release(monkeypatch):
    from countermap import sources

    monkeypatch.setattr(sources, "read_text", _fake_read_text(
        {sources.DEFAULT_URLS["d3fend_version"]: json.dumps({"version": "1.6.0", "ontology_version": "1.6.0"})}))
    onto, maps = sources.resolve_d3fend()
    assert onto.version == maps.version == "1.6.0"
    assert onto.url == "https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend.ttl"
    assert onto.fallbacks == ["https://raw.githubusercontent.com/d3fend/d3fend-ontology/1.6.0/src/ontology/d3fend-protege.ttl"]
    assert maps.url == "https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend-full-mappings.json"
    assert maps.optional


def test_resolve_d3fend_falls_back_to_changelog_then_to_nothing(monkeypatch):
    from countermap import sources

    changelog = "# Changelog\n\n## Version - 1.5.0 - 2026-07-31\n\n## Version - 1.4.0 - 2026-03-31\n"
    monkeypatch.setattr(sources, "read_text", _fake_read_text({sources.DEFAULT_URLS["d3fend_changelog"]: changelog}))
    onto, maps = sources.resolve_d3fend()
    assert onto.version == "1.5.0" and maps.url.endswith("/ontologies/d3fend/1.5.0/d3fend-full-mappings.json")

    monkeypatch.setattr(sources, "read_text", _fake_read_text({}))
    onto, maps = sources.resolve_d3fend()
    assert onto.version is None and onto.url == sources.DEFAULT_URLS["d3fend_ontology_latest"]
    assert maps.url is None
    monkeypatch.setenv("COUNTERMAP_URL_D3FEND_MAPPINGS", "/mirror/d3fend-full-mappings.json")
    assert sources.resolve_d3fend()[1].url == "/mirror/d3fend-full-mappings.json"


@pytest.mark.live
def test_live_build_from_upstream(tmp_path):
    """Downloads real data. Run with: pytest -m live"""
    from countermap.ingest import build
    from countermap.query import Countermap
    from countermap.sources import resolve_all

    db = tmp_path / "live.db"
    build(db, resolve_all(), tmp_path / "cache", log=print)
    c = Countermap(db)
    assert c.lookup("T1003.001")["name"] == "LSASS Memory"
    assert c.datasets()["active_object_counts"]["attack"]["technique"] > 800
