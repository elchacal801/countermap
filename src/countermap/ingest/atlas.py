"""Ingest MITRE ATLAS from the v6 YAML format published in mitre-atlas/atlas-data."""

from __future__ import annotations

from pathlib import Path

import yaml

from ..db import GraphWriter

ATLAS_URL = "https://atlas.mitre.org/{section}/{id}"
SECTION = {"tactic": "tactics", "technique": "techniques", "mitigation": "mitigations", "case-study": "studies"}


def ingest_atlas(writer: GraphWriter, path: Path, source_key: str = "atlas") -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    fmt = str(data.get("format-version", ""))
    if not fmt.startswith("6"):
        raise ValueError(f"unsupported ATLAS format-version {fmt!r}; expected 6.x")
    version = str(data["collection"].get("version"))
    nodes = edges = 0

    for section, kind in (("tactics", "tactic"), ("techniques", "technique"), ("mitigations", "mitigation"), ("case-studies", "case-study")):
        for ext_id, obj in (data.get(section) or {}).items():
            extra: dict = {}
            if kind == "technique":
                extra["subtechnique"] = ext_id.count(".") > 1
                if obj.get("maturity"):
                    extra["maturity"] = obj["maturity"]
            if kind == "mitigation":
                for key in ("categories", "lifecycle-phases"):
                    if obj.get(key):
                        extra[key.replace("-", "_")] = obj[key]
            writer.add_node(
                f"atlas:{ext_id}",
                framework="atlas",
                kind=kind,
                ext_id=ext_id,
                name=obj.get("name", ext_id),
                description=obj.get("description"),
                url=ATLAS_URL.format(section=SECTION[kind], id=ext_id),
                domains=["atlas"],
                platforms=obj.get("platforms"),
                deprecated=bool(obj.get("deprecated")),
                version=version,
                modified=str(obj.get("modified-date")) if obj.get("modified-date") else None,
                source=source_key,
                extra=extra,
            )
            nodes += 1
            ref = obj.get("attack-reference")
            if kind == "technique" and isinstance(ref, dict) and ref.get("id"):
                writer.add_edge(
                    f"atlas:{ext_id}",
                    "references_attack",
                    f"attack:{ref['id']}",
                    source=source_key,
                    detail={"url": ref.get("url")},
                )
                edges += 1

    relmap = {"achieves": "in_tactic", "specializes": "subtechnique_of", "mitigates": "mitigates", "employs": "employs"}
    for by_source in (data.get("relationships") or {}).values():
        for rels in by_source.values():
            for rel in rels:
                rtype = rel.get("relationship-type")
                if rtype == "sequences":
                    tactic = f"atlas:{rel['target']}"
                    if writer.has_node(tactic) and rel.get("position") is not None:
                        writer.nodes[tactic]["extra"]["order"] = rel["position"]
                    continue
                mapped = relmap.get(rtype)
                if not mapped:
                    continue
                detail = None
                if rtype == "employs":
                    detail = {
                        "steps": [
                            {
                                "step": rel.get("step-id"),
                                "tactic": rel.get("tactic"),
                                "leads_to": rel.get("leads-to"),
                                "description": (rel.get("description") or "")[:600],
                            }
                        ]
                    }
                writer.add_edge(f"atlas:{rel['source']}", mapped, f"atlas:{rel['target']}", source=source_key, detail=detail)
                edges += 1

    return {"source": source_key, "version": version, "nodes": nodes, "edges": edges}
