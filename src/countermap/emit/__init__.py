"""Output emitters. Every machine format is validated before it is returned."""

from __future__ import annotations

from typing import Any

from ..query import Countermap
from ..scenario import Scenario, resolve_scenario
from .attack_flow import render_attack_flow
from .cad import render_cad
from .mermaid import render_mermaid
from .navigator import navigator_layers
from .validate import validate_attack_flow, validate_cad

FORMATS = ("cad", "attack_flow", "mermaid", "navigator")


class RenderError(ValueError):
    pass


ANALYTIC_DESCRIPTION_CHARS = 300


def _short(text: str | None, chars: int) -> str | None:
    if not text or len(text) <= chars:
        return text
    return text[: chars - 1].rstrip() + "…"


def _flatten_detection(d: dict[str, Any]) -> dict[str, Any]:
    """One detection strategy as its ID, name, platforms and unique log sources (analytics merged).

    Each log source keeps the platforms of the analytics that use it, so a reader knows where to look.
    ``analytics`` lists each analytic with its platforms, a shortened description and the names of its
    tunable fields.
    """
    platforms = sorted({p for an in d["analytics"] for p in an["platforms"]})
    sources: dict[tuple, dict[str, Any]] = {}
    for an in d["analytics"]:
        for ls in an["log_sources"]:
            key = (ls.get("name"), ls.get("channel"), ls.get("data_component"))
            entry = sources.setdefault(key, {"log_source": key[0], "channel": key[1], "data_component": key[2],
                                             "platforms": []})
            entry["platforms"] = sorted(set(entry["platforms"]) | set(an["platforms"]))
    analytics = [{"id": an["id"], "platforms": an["platforms"],
                  "description": _short(an.get("description"), ANALYTIC_DESCRIPTION_CHARS),
                  "tunables": [m["field"] for m in an.get("mutable_elements", [])]} for an in d["analytics"]]
    return {"id": d["id"], "name": d["name"], "platforms": platforms, "log_sources": list(sources.values()),
            "analytics": analytics}


def render(spec: Scenario | dict, c: Countermap, formats: list[str] | None = None,
           *, timestamp: str | None = None, scope: str = "incident") -> dict[str, Any]:
    formats = list(formats or FORMATS)
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise RenderError(f"unknown format(s) {unknown}; choose from {list(FORMATS)}")
    rs = resolve_scenario(spec, c)
    out: dict[str, Any] = {"title": rs.title, "warnings": list(rs.warnings)}
    if rs.omitted:
        out["countermeasures_omitted_per_step"] = rs.omitted
    out["countermeasure_links"] = [
        {"step": l.step_id, "d3fend_id": l.d3fend_id, "name": l.d3fend_name, "tactic": l.tactic,
         "provenance": l.provenance, "via": l.via,
         "artifact_path": (f"{(l.path or {}).get('off_rel')} {(l.path or {}).get('off_artifact')} / "
                           f"{(l.path or {}).get('def_rel')} {(l.path or {}).get('def_artifact')}") if l.path else None}
        for l in rs.links
    ]
    # The mitigations MITRE links to each step's technique (official ATT&CK and ATLAS relationships).
    mitigations = {s.id: c.mitigations(s.node_id) for s in rs.steps}
    out["step_mitigations"] = [{"step": s.id, "technique": s.technique_id, "mitigations": mitigations[s.id]}
                               for s in rs.steps]
    # ATT&CK detection strategies per step, flattened to the platforms and log sources an analyst hunts in.
    detections = {s.id: [_flatten_detection(d) for d in c.detection_strategies(s.node_id)] for s in rs.steps}
    out["step_detections"] = [{"step": s.id, "technique": s.technique_id, "detection_strategies": detections[s.id]}
                              for s in rs.steps]
    if "cad" in formats:
        cad = render_cad(rs, published=timestamp)
        errors = validate_cad(cad)
        if errors:
            raise RenderError("CAD output failed schema validation: " + "; ".join(errors[:5]))
        out["cad"] = cad
        unknown_to_d3fend = [s.technique_id for s in rs.steps if s.framework in ("attack", "atlas")
                             and rs.d3fend_known_ids and s.technique_id not in rs.d3fend_known_ids]
        if unknown_to_d3fend:
            out["warnings"].append(
                f"Not in the loaded D3FEND ontology ({rs.versions.get('d3fend-ontology')}), so drawn in CAD "
                f"without a D3FEND class: {', '.join(unknown_to_d3fend)}"
            )
    if "attack_flow" in formats:
        flow = render_attack_flow(rs, c, scope=scope, timestamp=timestamp)
        errors = validate_attack_flow(flow)
        if errors:
            raise RenderError("Attack Flow output failed validation: " + "; ".join(errors[:5]))
        out["attack_flow"] = flow
    if "mermaid" in formats:
        out["mermaid"] = render_mermaid(rs)
    if "navigator" in formats:
        nav = navigator_layers(c, [s.node_id for s in rs.steps], name=rs.title, description=rs.description,
                               comments={s.node_id: (s.description or "")[:300] for s in rs.steps if s.description},
                               metadata={s.node_id: [{"name": "mitigation", "value": f"{m['id']} {m['name']}"}
                                                     for m in mitigations[s.id]]
                                         + [{"name": "detection", "value": f"{d['id']} {d['name']}"}
                                            for d in detections[s.id]] for s in rs.steps})
        out["navigator"] = nav["layers"]
        out["warnings"].extend(nav["warnings"])
    return out
