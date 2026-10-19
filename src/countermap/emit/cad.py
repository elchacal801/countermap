"""Render a resolved scenario as a D3FEND CAD graph (JSON, per the published CAD schema).

Layout: attack steps across the top in sequence order, the digital artifacts they
act on in the middle row, and D3FEND countermeasures on the bottom row, so every
countermeasure reaches an attack step through an artifact (the reasoning D3FEND
graphs are meant to show).

Two values the public schema does not pin down, edge handle ids and
``cad_schema_version``, default to what D3FEND CAD itself writes ("source",
"target" and 1; checked against CAD 0.26.1 on 2026-10-15). If CAD changes them,
export any graph with a connection and run ``countermap calibrate-cad <file>``.

CAD sizes each node to fit its text and property table, so the layout spaces
nodes for what CAD draws (an attack step with its properties is about 500 x 300),
not for the nominal ``measured`` box, which CAD recomputes on load.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path
from typing import Any

from ..scenario import ResolvedScenario

DEFAULT_CALIBRATION = {
    "cad_schema_version": 1,
    "source_handle": "source",
    "target_handle": "target",
    "marker": "arrowclosed",
    "calibrated": False,
}
NODE_W, NODE_H = 240, 90  # nominal ``measured`` size only
COL_PITCH = 580  # horizontal distance between node columns in every row
STEP_ROW_PITCH = 360  # vertical distance between steps that share a column
ARTIFACT_GAP = 60  # from the bottom of the step rows to the artifact row
COUNTER_GAP = 300  # from the artifact row to the countermeasure row


def calibration_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(os.environ.get("COUNTERMAP_CAD_CALIBRATION") or Path(base) / "countermap" / "cad-calibration.json")


def load_calibration() -> dict[str, Any]:
    path = calibration_path()
    if path.exists():
        try:
            return {**DEFAULT_CALIBRATION, **json.loads(path.read_text(encoding="utf-8"))}
        except (OSError, ValueError):
            pass
    return dict(DEFAULT_CALIBRATION)


def calibrate_from_export(exported: dict[str, Any]) -> dict[str, Any]:
    """Learn handle ids, marker type and schema version from a graph exported by D3FEND CAD."""
    edges = exported.get("edges") or []
    if not edges:
        raise ValueError("the exported graph has no edges; export a graph with at least one connection")
    from collections import Counter

    src = Counter(e.get("sourceHandle") for e in edges if e.get("sourceHandle"))
    dst = Counter(e.get("targetHandle") for e in edges if e.get("targetHandle"))
    marker = Counter((e.get("markerEnd") or {}).get("type") for e in edges if e.get("markerEnd"))
    return {
        "cad_schema_version": (exported.get("meta") or {}).get("cad_schema_version", DEFAULT_CALIBRATION["cad_schema_version"]),
        "source_handle": src.most_common(1)[0][0] if src else DEFAULT_CALIBRATION["source_handle"],
        "target_handle": dst.most_common(1)[0][0] if dst else DEFAULT_CALIBRATION["target_handle"],
        "marker": marker.most_common(1)[0][0] if marker else DEFAULT_CALIBRATION["marker"],
        "calibrated": True,
        "d3fend_version_seen": (exported.get("meta") or {}).get("d3fend_version"),
    }


def _prop(label: str | None, iri: str | None, props: dict[str, str]) -> str | None:
    if iri:
        return iri if iri.startswith("d3f:") else f"d3f:{iri}"
    if label and label in props:
        return props[label]
    return None


def render_cad(rs: ResolvedScenario, *, published: str | None = None, calibration: dict | None = None) -> dict[str, Any]:
    cal = calibration or load_calibration()
    published = published or _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: dict[str, str] = {}

    def add_node(key: str, ntype: str, label: str, x: float, y: float, *, d3f_class: str | None,
                 sequence: str = "0", props: list[list[str]] | None = None) -> str:
        if key in node_ids:
            return node_ids[key]
        nid = f"n{len(nodes) + 1}"
        data: dict[str, Any] = {"label": label, "sequence": sequence, "user_properties": props or []}
        if d3f_class:
            data["d3f_class"] = d3f_class
        nodes.append({
            "id": nid, "type": ntype, "position": {"x": float(x), "y": float(y)}, "data": data,
            "measured": {"width": NODE_W, "height": NODE_H}, "selected": False, "dragging": False,
        })
        node_ids[key] = nid
        return nid

    def add_edge(src: str, dst: str, label: str, d3f_property: str | None) -> None:
        key = (src, dst, label)
        if any((e["source"], e["target"], e["data"]["label"]) == key for e in edges):
            return
        data = {"label": label}
        if d3f_property:
            data["d3f_property"] = d3f_property
        edges.append({
            "id": f"e{len(edges) + 1}", "source": src, "sourceHandle": cal["source_handle"],
            "target": dst, "targetHandle": cal["target_handle"], "data": data,
            "markerEnd": {"type": cal["marker"]}, "selected": False,
        })

    # Row 1: steps, columns by depth.
    row_in_col: dict[int, int] = {}
    order = sorted(rs.steps, key=lambda s: (s.depth, rs.steps.index(s)))
    d3fend_version = (rs.versions or {}).get("d3fend-ontology")
    for seq, step in enumerate(order, start=1):
        row = row_in_col.get(step.depth, 0)
        row_in_col[step.depth] = row + 1
        x, y = 40 + step.depth * COL_PITCH, 40 + row * STEP_ROW_PITCH
        props = [["framework", step.framework], ["technique_id", step.technique_id], ["step_id", step.id]]
        # Only name a D3FEND class that exists: the loaded ontology may predate the technique.
        d3f_class = None
        if step.framework in ("attack", "atlas"):
            if not rs.d3fend_known_ids or step.technique_id in rs.d3fend_known_ids:
                d3f_class = f"d3f:{step.technique_id}"
            else:
                props.append(["d3fend_class", f"none: not in the loaded D3FEND ontology ({d3fend_version})"])
        if step.tactics:
            props.append(["tactics", ", ".join(t["name"] for t in step.tactics)])
        if step.description:
            props.append(["description", step.description])
        if step.assets:
            props.append(["assets", ", ".join(step.assets)])
        label = f"{step.technique_id} {step.label}"
        add_node(f"step:{step.id}", "attack-node", label, x, y, d3f_class=d3f_class, sequence=str(seq), props=props)

    for step in rs.steps:
        for prev in step.after:
            add_edge(node_ids[f"step:{prev}"], node_ids[f"step:{step.id}"], "precedes", "d3f:precedes")

    steps_bottom = 40 + max(row_in_col.values(), default=1) * STEP_ROW_PITCH
    artifact_y = steps_bottom + ARTIFACT_GAP
    counter_y = artifact_y + COUNTER_GAP
    artifact_col = counter_col = 0

    def artifact(label: str | None, iri: str | None) -> str | None:
        nonlocal artifact_col
        if not label and not iri:
            return None
        local = iri or (rs.artifact_iris.get((label or "").lower()) or "").replace("d3f:", "") or None
        key = f"artifact:{local or label}"
        if key in node_ids:
            return node_ids[key]
        nid = add_node(key, "artifact-node", label or local, 40 + artifact_col * COL_PITCH, artifact_y,
                       d3f_class=f"d3f:{local}" if local else None)
        artifact_col += 1
        return nid

    # One countermeasure node per (D3FEND technique, provenance class), so a countermeasure that is
    # official for one step and derived for another is never drawn as if it were official for both.
    def cm_key(link) -> str:
        return f"cm:{link.d3fend_id}:{'official' if link.provenance == 'official' else link.provenance}"

    grouped: dict[str, list] = {}
    for link in rs.links:
        grouped.setdefault(cm_key(link), []).append(link)
    for key, links in grouped.items():
        first = links[0]
        suffix = "" if first.provenance == "official" else f" [{first.provenance}]"
        props = [["d3fend_id", first.d3fend_id], ["provenance", first.provenance],
                 ["steps", ", ".join(dict.fromkeys(l.step_id for l in links))]]
        if first.tactic:
            props.append(["tactic", first.tactic])
        vias = list(dict.fromkeys(l.via for l in links if l.via))
        if vias:
            props.append(["via", "; ".join(vias)])
        add_node(key, "countermeasure-node", f"{first.d3fend_name} ({first.d3fend_id}){suffix}",
                 40 + counter_col * COL_PITCH, counter_y, d3f_class=first.d3fend_iri, props=props)
        counter_col += 1

    for link in rs.links:
        step_node = node_ids[f"step:{link.step_id}"]
        cm_node = node_ids[cm_key(link)]
        marker = "" if link.provenance == "official" else f" ({link.provenance})"
        path = link.path or {}
        off_art = artifact(path.get("off_artifact"), path.get("off_artifact_iri"))
        def_art = artifact(path.get("def_artifact"), path.get("def_artifact_iri"))
        if off_art is None and def_art is None:
            add_edge(cm_node, step_node, "counters (analyst assertion, no D3FEND artifact path)", None)
            continue
        if off_art:
            add_edge(step_node, off_art, (path.get("off_rel") or "acts on") + marker,
                     _prop(path.get("off_rel"), path.get("off_rel_iri"), rs.d3fend_properties))
        if def_art:
            add_edge(cm_node, def_art, path.get("def_rel") or "acts on",
                     _prop(path.get("def_rel"), path.get("def_rel_iri"), rs.d3fend_properties))
        if off_art and def_art and off_art != def_art:
            add_edge(off_art, def_art, "related artifact (D3FEND inference)", "d3f:associated-with")

    versions = rs.versions or {}
    meta = {
        "title": rs.title,
        "authors": rs.authors or [],
        "orgs": [],
        "description": rs.description or "Generated by Countermap from MITRE knowledge bases.",
        "article": "",
        "d3fend_version": str(versions.get("d3fend-ontology") or "unknown"),
        "cad_schema_version": cal["cad_schema_version"],
        "published_date": published,
        "references": sorted({s.url for s in rs.steps if s.url}),
    }
    return {"meta": meta, "nodes": nodes, "edges": edges}
