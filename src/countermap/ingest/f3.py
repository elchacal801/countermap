"""Ingest the MITRE Fight Fraud Framework (F3) STIX bundle.

F3 reuses some ATT&CK technique and tactic IDs (for example T1056, TA0005) but
publishes its own fraud-specific definitions and tactic placement. Those objects
stay in the ``f3:`` namespace and get an official ``reuses_attack_id`` edge to the
ATT&CK object with the same ID; they are never treated as the same behavior.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..db import GraphWriter

ATTACK_ID = re.compile(r"^(T\d{4}(\.\d{3})?|TA\d{4})$")


def _ref(obj: dict) -> dict | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-f3" and ref.get("external_id"):
            return ref
    for ref in obj.get("external_references", []):
        if ref.get("external_id"):
            return ref
    return None


def ingest_f3(writer: GraphWriter, path: Path, source_key: str = "f3") -> dict:
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = bundle["objects"]
    collection = next((o for o in objects if o["type"] == "x-mitre-collection"), {})
    version = collection.get("x_mitre_version")
    stix_to_node: dict[str, str] = {}
    tactics: dict[str, str] = {}
    nodes = edges = 0

    for obj in objects:
        if obj["type"] not in ("attack-pattern", "x-mitre-tactic"):
            continue
        ref = _ref(obj)
        if ref is None:
            continue
        ext_id = ref["external_id"]
        node_id = f"f3:{ext_id}"
        kind = "technique" if obj["type"] == "attack-pattern" else "tactic"
        extra: dict = {}
        if kind == "tactic":
            extra["shortname"] = obj.get("x_mitre_shortname")
            tactics[obj.get("x_mitre_shortname")] = node_id
        else:
            extra["subtechnique"] = bool(obj.get("x_mitre_is_subtechnique"))
        stix_to_node[obj["id"]] = node_id
        writer.add_node(
            node_id,
            framework="f3",
            kind=kind,
            ext_id=ext_id,
            name=obj.get("name", ext_id),
            description=obj.get("description"),
            url=ref.get("url"),
            domains=["f3"],
            platforms=obj.get("x_mitre_platforms"),
            deprecated=obj.get("x_mitre_deprecated", False),
            revoked=obj.get("revoked", False),
            version=version,
            modified=obj.get("modified"),
            stix_id=obj["id"],
            source=source_key,
            extra=extra,
        )
        nodes += 1

    for matrix in (o for o in objects if o["type"] == "x-mitre-matrix"):
        for position, ref in enumerate(matrix.get("tactic_refs", [])):
            node_id = stix_to_node.get(ref)
            if node_id:
                writer.nodes[node_id]["extra"].setdefault("order", position)

    for obj in objects:
        node_id = stix_to_node.get(obj["id"])
        if obj["type"] == "attack-pattern" and node_id:
            for phase in obj.get("kill_chain_phases", []):
                tactic = tactics.get(phase["phase_name"])
                if tactic:
                    writer.add_edge(node_id, "in_tactic", tactic, source=source_key)
                    edges += 1
        elif obj["type"] == "relationship" and obj["relationship_type"] == "subtechnique-of":
            src, dst = stix_to_node.get(obj["source_ref"]), stix_to_node.get(obj["target_ref"])
            if src and dst:
                writer.add_edge(src, "subtechnique_of", dst, source=source_key)
                edges += 1

    # Official crosswalk: F3 deliberately reuses these ATT&CK IDs.
    for node_id in list(stix_to_node.values()):
        ext_id = node_id.split(":", 1)[1]
        if ATTACK_ID.match(ext_id):
            writer.add_edge(
                node_id,
                "reuses_attack_id",
                f"attack:{ext_id}",
                source=source_key,
                detail={"note": "F3 reuses the ATT&CK ID with a fraud-specific definition and tactic placement."},
            )
            edges += 1

    return {"source": source_key, "version": version, "nodes": nodes, "edges": edges}
