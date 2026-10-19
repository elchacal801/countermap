"""Read-only MCP server.

Security posture:
- The database is opened read-only. Tools never touch the network, the shell or
  the filesystem beyond that file.
- Tool outputs include upstream MITRE text. Treat it as data, not instructions.
- Every result says which dataset and version it came from, and whether a
  cross-framework link is official or derived.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__
from .diff import diff_snapshots
from .emit import FORMATS, RenderError, render
from .emit.navigator import navigator_layers
from .ingest import prev_path
from .query import Countermap, NotFound, _distinct
from .sources import default_db_path

INSTRUCTIONS = """Countermap answers questions about MITRE ATT&CK (Enterprise, Mobile, ICS), D3FEND, ATLAS and F3 from a local, versioned snapshot.
Rules for agents:
- Always cite IDs and the dataset version from results; call `datasets` if you need versions.
- Results label cross-framework links as provenance=official (published by MITRE) or provenance=derived (composed through the path in `via`). Never present derived links as MITRE's.
- An empty D3FEND result carries `gap_reason`. `unavailable` means the D3FEND data is not loaded: report it as unknown, not as a gap, and suggest a rebuild. Any other reason is a coverage gap, not proof that no defense applies.
- F3 reuses some ATT&CK IDs with fraud-specific definitions; f3:T1056 is not identical to attack:T1056.
- telemetry_coverage and rule_coverage classes and rankings are Countermap's computations over MITRE's data; quote their `basis` and never present them as MITRE's.
- To draw diagrams, write a scenario spec and call `render_scenario`; never hand-write CAD JSON, Attack Flow STIX or Navigator layers."""

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

log = logging.getLogger("countermap")
server = MCPServer("countermap", instructions=INSTRUCTIONS, version=__version__)
_state: dict[str, Any] = {}


def _db() -> Countermap:
    path = Path(os.environ.get("COUNTERMAP_DB") or default_db_path())
    cached = _state.get("db")
    if cached is None or cached.path != path:
        _state["db"] = Countermap(path)
    return _state["db"]


def _safe(fn, *args, **kwargs) -> dict[str, Any]:
    """Run a tool body. Every failure becomes {"error": ...}; agents never see tracebacks."""
    try:
        return fn(*args, **kwargs)
    except (NotFound, RenderError, FileNotFoundError, ValueError) as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - last line of defense for agent-facing calls
        log.exception("tool failed")
        return {"error": f"internal error ({type(exc).__name__}); see server log"}


def _call(method: str, *args, **kwargs) -> dict[str, Any]:
    return _safe(lambda: getattr(_db(), method)(*args, **kwargs))


def _cap(items: list | None, n: int = 300) -> list:
    return list(items or [])[:n]


# The coverage tools drop repeated entries before capping, and cap above the query's own limits, so the
# query sees any overflow and says what it cut (as compare_actors does) instead of losing entries silently.
# Larger coverage layers are left to the CLI's --layer FILE: about 120 techniques keeps a response near 75 KB,
# under Claude Code's default MCP output limit (a 230-technique layer is about 142 KB, some 36k tokens).
LAYER_MAX_TECHNIQUES = 120


def _distinct_cap(items: list | None, n: int) -> list[str]:
    return _distinct(items)[:n]


@server.tool(annotations=READ_ONLY)
def datasets() -> dict[str, Any]:
    """Loaded datasets, their versions, SHA-256 hashes and licenses, object counts, and build warnings
    (for example cross-framework links that point at objects revoked in the loaded ATT&CK version)."""
    return _call("datasets")


@server.tool(annotations=READ_ONLY)
def search(query: str, framework: Literal["attack", "d3fend", "atlas", "f3"] | None = None,
           kind: str | None = None, limit: int = 10, include_inactive: bool = False) -> dict[str, Any]:
    """Full-text search across names, aliases, IDs and descriptions. kind examples: technique, group,
    software, campaign, mitigation, tactic, detection-strategy, data-component, countermeasure, artifact, case-study."""
    return _call("search", query, framework=framework, kind=kind, limit=limit, include_inactive=include_inactive)


@server.tool(annotations=READ_ONLY)
def lookup(ref: str, framework: Literal["attack", "d3fend", "atlas", "f3"] | None = None) -> dict[str, Any]:
    """Look up any object by ID (T1003.001, G0016, AML.T0051, F1001, D3-FH, f3:T1056), name or alias (APT29).
    Revoked IDs are followed to their replacement and flagged."""
    return _call("lookup", ref, framework=framework)


@server.tool(annotations=READ_ONLY)
def technique_context(technique: str, limit: int = 15) -> dict[str, Any]:
    """Everything about one technique: tactics, parent/sub-techniques, groups/software/campaigns that use it,
    mitigations, ATT&CK detection strategies with analytics and log sources, D3FEND countermeasures, and crosswalk links."""
    return _call("technique_context", technique, limit=max(1, min(limit, 100)))


@server.tool(annotations=READ_ONLY)
def countermeasures(technique: str, d3fend_tactic: str | None = None, include_derived: bool = True,
                    limit: int = 25) -> dict[str, Any]:
    """D3FEND countermeasures for an ATT&CK, ATLAS or F3 technique, with the digital-artifact path that links them.
    Official results come from MITRE's published D3FEND inference; derived results show their `via` path
    (parent/sub-technique, revoked ID, or an F3/ATLAS link to ATT&CK). When the list is empty, `gap_reason` says
    why: unavailable (the D3FEND data is not loaded in this database; not a gap, suggest a rebuild), predates (the
    loaded D3FEND release predates the technique), no_mapping (D3FEND maps nothing to it), f3_native (an F3
    technique with no ATT&CK link) or none_in_tactic (countermeasures exist, none in d3fend_tactic)."""
    return _call("countermeasures", technique, tactic=d3fend_tactic, include_derived=include_derived, limit=limit)


@server.tool(annotations=READ_ONLY)
def crosswalk(ref: str) -> dict[str, Any]:
    """Cross-framework links for an object (ATLAS references ATT&CK, F3 reuses ATT&CK IDs), with provenance
    and flags when the linked ATT&CK object is revoked, deprecated or missing in the loaded version."""
    return _call("crosswalk", ref)


@server.tool(annotations=READ_ONLY)
def actor_techniques(actor: str, include_software: bool = False) -> dict[str, Any]:
    """Techniques used by an ATT&CK group, software or campaign (ID, name or alias). With include_software,
    adds techniques of software the actor uses, labeled derived."""
    return _call("actor_techniques", actor, include_software=include_software)


@server.tool(annotations=READ_ONLY)
def compare_actors(actors: list[str], include_software: bool = False) -> dict[str, Any]:
    """Technique overlap between 2-8 groups, software or campaigns: shared, unique, pairwise Jaccard."""
    return _call("compare_actors", _cap(actors, 50), include_software=include_software)


@server.tool(annotations=READ_ONLY)
def coverage_gaps(techniques: list[str]) -> dict[str, Any]:
    """For a list of techniques (for example from an incident or threat model), count mitigations, detection
    strategies and D3FEND countermeasures, and list which have none. Each entry's d3fend_gap_reason says why it
    has no D3FEND countermeasures (as in `countermeasures`). IDs in summary.d3fend_unavailable have null D3FEND
    counts because the D3FEND data is not loaded: report them as unknown, not as gaps. summary.d3fend_predates
    lists the techniques the loaded D3FEND release predates (they are also in no_official_d3fend)."""
    return _call("coverage_gaps", list(techniques or []))


@server.tool(annotations=READ_ONLY)
def telemetry_coverage(log_sources: list[str] | None = None, data_components: list[str] | None = None,
                       platform: str | None = None, techniques: list[str] | None = None, actor: str | None = None,
                       include_software: bool = False,
                       domain: Literal["enterprise-attack", "mobile-attack", "ics-attack"] | None = None,
                       layer: bool = False, limit: int = 50) -> dict[str, Any]:
    """What the logs you collect can detect, and where you are blind. Matches your telemetry against the log
    sources MITRE lists on each ATT&CK analytic and classifies each target technique as covered, partial, blind,
    no_analytic_for_platform or no_detection_strategy, with the analytics behind it and the log sources missing.

    log_sources: names as on ATT&CK analytics, optionally with a channel ("WinEventLog:Sysmon",
    "WinEventLog:Sysmon EventCode=10"); a name alone matches every channel. data_components: IDs or names
    (DC0032, "Process Creation"). Target: techniques, or an actor (group, software or campaign), or every
    technique on the platform when neither is given, in one ATT&CK domain or all three (the default).
    layer=true adds a Navigator layer (covered 2, partial 1, blind 0) for up to 120 techniques; for more, the
    result says to run `countermap coverage ... --layer FILE`. The classification is Countermap's computation
    over MITRE's references, not MITRE's."""
    return _call("telemetry_coverage", log_sources=_distinct_cap(log_sources, 1000),
                 data_components=_distinct_cap(data_components, 1000), platform=platform,
                 techniques=_distinct_cap(techniques, 1000), actor=actor, include_software=include_software,
                 domain=domain, layer=layer, limit=max(1, min(limit, 300)), max_layer_techniques=LAYER_MAX_TECHNIQUES)


@server.tool(annotations=READ_ONLY)
def rule_coverage(techniques: list[str], scope_actors: list[str] | None = None, platform: str | None = None,
                  tactics: list[str] | None = None,
                  domain: Literal["enterprise-attack", "mobile-attack", "ics-attack"] = "enterprise-attack",
                  layer: bool = False, limit: int = 50) -> dict[str, Any]:
    """What your detection rules cover, and what to build next, ranked by threat-group use. Pass the ATT&CK
    technique IDs your rules are mapped to. Each in-scope technique is covered (its ID is listed), partial (its
    parent is listed, or some of its sub-techniques are) or uncovered. Gaps are ranked uncovered first, then
    partial, by how many groups use the technique, then by campaigns. Each entry lists its tactics, its group
    count (total and direct) with examples marked direct or derived, detection strategies and the data
    components its analytics need.

    Scope: the domain's active techniques, filtered by platform and tactics (names or IDs); with scope_actors
    (groups, software or campaigns) only their techniques, ranked by how many of them use each, then by the
    overall group count. layer=true adds a Navigator layer (covered 2, partial 1, uncovered 0) for up to 120
    techniques; for more, the result says to run `countermap rules-coverage ... --layer FILE`.
    Group counts are the groups ATT&CK links to the technique directly, or through software they use (the latter
    derived by Countermap), not prevalence; the ranking uses the total. The status and ranking are Countermap's
    computation."""
    return _call("rule_coverage", _distinct_cap(techniques, 5000),
                 scope_actors=_distinct_cap(scope_actors, 200) or None, platform=platform,
                 tactics=_distinct_cap(tactics, 100) or None, domain=domain, layer=layer,
                 limit=max(1, min(limit, 300)), max_layer_techniques=LAYER_MAX_TECHNIQUES)


@server.tool(annotations=READ_ONLY)
def version_diff(framework: Literal["attack", "d3fend", "atlas", "f3"] = "attack", kind: str | None = None,
                 limit: int = 50) -> dict[str, Any]:
    """What changed between the previous build and the current one: added, removed, revoked (with replacements),
    deprecated, renamed, tactic changes. Requires a previous snapshot (created automatically on rebuild)."""
    def run() -> dict[str, Any]:
        db = _db()
        prev = prev_path(db.path)
        if not prev.exists():
            return {"error": "No previous snapshot. Rebuild after an upstream release, or run `countermap diff OLD NEW`."}
        return diff_snapshots(prev, db.path, framework=framework, kind=kind, limit=max(1, min(limit, 500)))

    return _safe(run)


@server.tool(annotations=READ_ONLY)
def navigator_layer(techniques: list[str] | None = None, actor: str | None = None, name: str = "Countermap layer",
                    description: str = "", scores: dict[str, float] | None = None) -> dict[str, Any]:
    """ATT&CK Navigator layer JSON (layer 4.5) for a technique list or an actor. F3 techniques go on an
    F3-domain layer. Returns one layer per domain plus warnings for anything that could not be placed."""
    def run() -> dict[str, Any]:
        db = _db()
        refs = _cap(techniques, 1000)
        title = name
        if actor:
            data = db.actor_techniques(actor)
            refs += [t["id"] for t in data["techniques"]]
            if title == "Countermap layer":
                title = f"{data['actor']['name']} ({data['actor']['ext_id']})"
        if not refs:
            return {"error": "provide techniques or an actor"}
        return navigator_layers(db, refs, name=title[:200], description=description[:2000], scores=scores)

    return _safe(run)


@server.tool(annotations=READ_ONLY)
def render_scenario(spec: dict[str, Any], formats: list[Literal["cad", "attack_flow", "mermaid", "navigator"]] | None = None,
                    scope: Literal["incident", "campaign", "threat-actor", "malware", "emulation-plan", "attack-tree", "other"] = "incident") -> dict[str, Any]:
    """Validate a scenario spec against the loaded data and render it as D3FEND CAD JSON, Attack Flow 2.0 STIX,
    Mermaid and/or Navigator layers. Every ID is checked; revoked IDs are replaced with warnings. The result also
    lists, per step, the ATT&CK or ATLAS mitigations MITRE links to its technique (`step_mitigations`) and its
    ATT&CK detection strategies with platforms and log sources (`step_detections`). With countermeasures "auto",
    `steps_without_countermeasures` lists each step that got none, with its `gap_reason` (unavailable means the
    D3FEND data is not loaded, not a gap).

    spec = {"title": str, "description": str, "authors": [str],
            "steps": [{"id": "s1", "technique": "T1566.002", "name"?: str, "description"?: str,
                       "after": ["s0"], "assets": [str]}],
            "countermeasures": "auto" | "none" | [{"id": "D3-UA", "targets": ["s1"]}],
            "max_countermeasures_per_step": 3, "d3fend_tactics": ["Harden", "Detect"]}"""
    return _safe(lambda: render(spec, _db(), formats or list(FORMATS), scope=scope))


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
