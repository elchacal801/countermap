"""Ingest MITRE ATT&CK STIX 2.1 collections (Enterprise, Mobile, ICS)."""

from __future__ import annotations

import json
from pathlib import Path

from ..db import GraphWriter

KIND = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "course-of-action": "mitigation",
    "intrusion-set": "group",
    "malware": "software",
    "tool": "software",
    "campaign": "campaign",
    "x-mitre-detection-strategy": "detection-strategy",
    "x-mitre-analytic": "analytic",
    "x-mitre-data-component": "data-component",
    "x-mitre-data-source": "data-source",
    "x-mitre-asset": "asset",
}

RELATION = {
    "uses": "uses",
    "mitigates": "mitigates",
    "detects": "detects",
    "subtechnique-of": "subtechnique_of",
    "revoked-by": "revoked_by",
    "attributed-to": "attributed_to",
    "targets": "targets",
}


def _ext_ref(obj: dict) -> dict | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name", "").startswith("mitre") and ref.get("external_id"):
            return ref
    return None


def ingest_attack(writer: GraphWriter, path: Path, source_key: str) -> dict:
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = bundle["objects"]
    collection = next((o for o in objects if o["type"] == "x-mitre-collection"), {})
    version = collection.get("x_mitre_version")
    domain = source_key.replace("attack-", "") + "-attack"

    stix_to_node: dict[str, str] = {}
    tactic_by_shortname: dict[str, str] = {}
    count = 0
    # Shared across the ATT&CK bundles of one build, for references that cross bundles.
    stix_index: dict[str, str] = writer.__dict__.setdefault("attack_stix_index", {})
    pending: list = writer.__dict__.setdefault("attack_pending_references", [])

    for obj in objects:
        kind = KIND.get(obj["type"])
        if kind is None:
            continue
        ref = _ext_ref(obj)
        if ref is None:
            continue
        ext_id = ref["external_id"]
        node_id = f"attack:{ext_id}"
        if obj["type"] == "course-of-action" and ext_id.startswith("T"):
            # Legacy (pre-2019) mitigations reuse their technique's ID, e.g. "T1033 Mitigation".
            # They are deprecated; keep them in their own namespace so they never shadow techniques.
            node_id = f"attack:mitigation:{ext_id}"
        existing = writer.nodes.get(node_id)
        if existing is not None and existing["stix_id"] != obj["id"]:
            # A different object already holds this ID (upstream data error, e.g. ICS publishes a
            # deprecated EKANS under S0017, which Enterprise uses for BISCUIT). Never merge them.
            alt = f"{node_id}@{domain}"
            writer.warnings.append(
                f"{source_key}: {obj.get('name')} ({obj['id']}) reuses {ext_id}, already used by "
                f"{existing['name']}; stored as {alt}"
            )
            node_id = alt
        stix_to_node[obj["id"]] = node_id
        extra: dict = {}
        if obj["type"] in ("malware", "tool"):
            extra["software_type"] = obj["type"]
        if obj["type"] == "attack-pattern":
            extra["subtechnique"] = bool(obj.get("x_mitre_is_subtechnique"))
        if obj["type"] == "x-mitre-tactic":
            extra["shortname"] = obj.get("x_mitre_shortname")
            tactic_by_shortname[obj.get("x_mitre_shortname")] = node_id
        if obj["type"] == "x-mitre-data-component" and obj.get("x_mitre_log_sources"):
            extra["log_sources"] = obj["x_mitre_log_sources"]
        if obj["type"] == "x-mitre-analytic" and obj.get("x_mitre_mutable_elements"):
            # The fields MITRE marks as tunable for the environment (allowlists, thresholds, time windows).
            extra["mutable_elements"] = [{"field": e.get("field"), "description": e.get("description")}
                                         for e in obj["x_mitre_mutable_elements"]]
        if obj["type"] == "campaign":
            for key, stix_key in (("first_seen", "first_seen"), ("last_seen", "last_seen"),
                                  ("first_seen_citation", "x_mitre_first_seen_citation"),
                                  ("last_seen_citation", "x_mitre_last_seen_citation")):
                if obj.get(stix_key):
                    extra[key] = obj[stix_key]
        aliases = obj.get("aliases") or obj.get("x_mitre_aliases") or []
        writer.add_node(
            node_id,
            framework="attack",
            kind=kind,
            ext_id=ext_id,
            name=obj.get("name", ext_id),
            description=obj.get("description"),
            url=ref.get("url"),
            domains=obj.get("x_mitre_domains") or [domain],
            platforms=obj.get("x_mitre_platforms"),
            aliases=aliases,
            deprecated=obj.get("x_mitre_deprecated", False),
            revoked=obj.get("revoked", False),
            version=obj.get("x_mitre_version"),
            modified=obj.get("modified"),
            stix_id=obj["id"],
            source=source_key,
            extra=extra,
        )
        count += 1

    # Tactic order from the matrix.
    for matrix in (o for o in objects if o["type"] == "x-mitre-matrix"):
        for position, ref in enumerate(matrix.get("tactic_refs", [])):
            node_id = stix_to_node.get(ref)
            if node_id and writer.has_node(node_id):
                writer.nodes[node_id]["extra"].setdefault("order", position)

    edges = 0
    for obj in objects:
        node_id = stix_to_node.get(obj["id"])
        if obj["type"] == "attack-pattern" and node_id:
            for phase in obj.get("kill_chain_phases", []):
                tactic = tactic_by_shortname.get(phase["phase_name"])
                if tactic:
                    writer.add_edge(node_id, "in_tactic", tactic, source=source_key)
                    edges += 1
        elif obj["type"] == "x-mitre-detection-strategy" and node_id:
            for ref in obj.get("x_mitre_analytic_refs", []):
                if ref in stix_to_node:
                    writer.add_edge(node_id, "has_analytic", stix_to_node[ref], source=source_key)
                    edges += 1
        elif obj["type"] == "x-mitre-analytic" and node_id:
            for log_ref in obj.get("x_mitre_log_source_references", []):
                detail = {"log_sources": [{"name": log_ref.get("name"), "channel": log_ref.get("channel")}]}
                dc = stix_to_node.get(log_ref.get("x_mitre_data_component_ref"))
                if dc:
                    writer.add_edge(node_id, "uses_data_component", dc, source=source_key, detail=detail)
                    edges += 1
                else:
                    # Another bundle may publish the data component (ICS analytics reference Enterprise-only
                    # ones). Resolved by resolve_cross_bundle_references once every bundle is loaded.
                    pending.append((node_id, log_ref.get("x_mitre_data_component_ref"), detail, source_key))
        elif obj["type"] == "x-mitre-data-component" and node_id:
            ds = stix_to_node.get(obj.get("x_mitre_data_source_ref"))
            if ds:
                writer.add_edge(node_id, "part_of_data_source", ds, source=source_key)
                edges += 1
        elif obj["type"] == "relationship":
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue
            rel = RELATION.get(obj["relationship_type"])
            src = stix_to_node.get(obj["source_ref"])
            dst = stix_to_node.get(obj["target_ref"])
            if rel and src and dst:
                writer.add_edge(src, rel, dst, source=source_key)
                edges += 1

    for stix_id, node_id in stix_to_node.items():
        stix_index.setdefault(stix_id, node_id)
    return {"source": source_key, "version": version, "nodes": count, "edges": edges}


def resolve_cross_bundle_references(writer: GraphWriter) -> int:
    """Second pass, after every ATT&CK bundle is loaded: link analytic log-source references whose data
    component is published in another bundle (by STIX ID, the same object), so the result does not depend on
    which bundle loads first. A reference no loaded bundle resolves becomes a build warning, never a silent drop.
    """
    index = writer.__dict__.get("attack_stix_index", {})
    linked = 0
    for analytic, ref, detail, source_key in writer.__dict__.pop("attack_pending_references", []):
        dc = index.get(ref)
        if dc:
            writer.add_edge(analytic, "uses_data_component", dc, source=source_key, detail=detail)
            linked += 1
            continue
        ls = detail["log_sources"][0]
        writer.warnings.append(
            f"{source_key}: analytic {writer.nodes[analytic]['ext_id']} references data component {ref} "
            f"(log source {ls['name']!r}, channel {ls['channel']!r}), which no loaded ATT&CK bundle publishes; "
            "that log source is not linked"
        )
    return linked
