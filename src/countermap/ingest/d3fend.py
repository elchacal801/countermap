"""Ingest MITRE D3FEND.

Two inputs, kept separate on purpose:

1. The ontology (TTL): defensive techniques with D3FEND IDs, tactics, digital
   artifacts and the artifact relations each defensive technique declares.
2. MITRE's published inference output (``d3fend-full-mappings.json``): which
   defensive techniques counter which offensive techniques, through which
   digital artifacts. This is the only source of ``counters`` edges.

Countermap does not run its own countermeasure inference. If the published
mappings cannot be fetched, lookups still work but countermeasure queries say
the mappings are unavailable instead of guessing.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from pathlib import Path

from rdflib import BNode, Graph, Literal, Namespace, URIRef
from rdflib.namespace import OWL, RDF, RDFS

from ..db import GraphWriter

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
D3FEND_URL = "https://d3fend.mitre.org/technique/d3f:{local}/"
ARTIFACT_URL = "https://d3fend.mitre.org/dao/artifact/d3f:{local}/"


def local_name(iri: str | None) -> str | None:
    if not iri:
        return None
    iri = str(iri)
    if iri.startswith("d3f:"):
        return iri[4:]
    return re.split(r"[#/]", iri)[-1] or None


def _text(graph: Graph, subject, predicate) -> str | None:
    value = graph.value(subject, predicate)
    return str(value) if value is not None else None


def ingest_d3fend_ontology(writer: GraphWriter, path: Path, source_key: str = "d3fend-ontology") -> dict:
    graph = Graph()
    graph.parse(str(path), format="turtle")

    ontology_iri = next(graph.subjects(RDF.type, OWL.Ontology), None)
    version = None
    if ontology_iri is not None:
        version = _text(graph, ontology_iri, OWL.versionInfo)

    named_parents: dict[URIRef, list[URIRef]] = defaultdict(list)
    children: dict[URIRef, list[URIRef]] = defaultdict(list)
    for sub, sup in graph.subject_objects(RDFS.subClassOf):
        if isinstance(sub, URIRef) and isinstance(sup, URIRef):
            named_parents[sub].append(sup)
            children[sup].append(sub)

    # Tactics.
    tactic_label: dict[URIRef, str] = {}
    for tactic in set(graph.subjects(RDFS.subClassOf, D3F.DefensiveTactic)):
        if not isinstance(tactic, URIRef):
            continue
        label = _text(graph, tactic, RDFS.label) or local_name(tactic)
        tactic_label[tactic] = label
        order = graph.value(tactic, D3F["display-order"])
        writer.add_node(
            f"d3fend:{label}",
            framework="d3fend",
            kind="tactic",
            ext_id=label,
            name=label,
            description=_text(graph, tactic, D3F.definition),
            url=f"https://d3fend.mitre.org/tactic/d3f:{local_name(tactic)}/",
            domains=["d3fend"],
            source=source_key,
            extra={"iri": f"d3f:{local_name(tactic)}", **({"order": int(order)} if order is not None else {})},
        )

    # Defensive techniques.
    d3id_of: dict[URIRef, str] = {}
    claimed: dict[str, URIRef] = {}
    duplicates: dict[str, list[str]] = defaultdict(list)
    for subject, d3id in sorted(graph.subject_objects(D3F["d3fend-id"]), key=lambda so: str(so[0])):
        if not (isinstance(subject, URIRef) and isinstance(d3id, Literal)):
            continue
        d3id = str(d3id).strip()
        if d3id in claimed:
            # Upstream assigns the same ID to several classes (seen for D3A-* analytic techniques).
            # Keep each class, disambiguated as ID@ClassName, instead of merging them.
            d3id_of[subject] = f"{d3id}@{local_name(subject)}"
            duplicates[d3id].append(local_name(subject))
        else:
            claimed[d3id] = subject
            d3id_of[subject] = d3id
    if duplicates:
        examples = "; ".join(
            f"{k}: {local_name(claimed[k])}, {', '.join(v)}" for k, v in sorted(duplicates.items())[:3]
        )
        writer.warnings.append(
            f"{source_key}: {len(duplicates)} D3FEND IDs are assigned to more than one class upstream "
            f"(e.g. {examples}); the extra classes are stored as ID@ClassName"
        )

    tactic_cache: dict[URIRef, str | None] = {}

    def direct_tactic(subject: URIRef) -> str | None:
        # Tactics are asserted either as a direct triple (x enables Harden) or as an
        # OWL restriction (x subClassOf [enables some Isolate]).
        for value in graph.objects(subject, D3F.enables):
            if value in tactic_label:
                return tactic_label[value]
        for node in graph.objects(subject, RDFS.subClassOf):
            if isinstance(node, BNode) and graph.value(node, OWL.onProperty) == D3F.enables:
                value = graph.value(node, OWL.someValuesFrom)
                if value in tactic_label:
                    return tactic_label[value]
        return None

    def tactic_of(subject: URIRef, seen: frozenset = frozenset()) -> str | None:
        if subject in tactic_cache:
            return tactic_cache[subject]
        result = direct_tactic(subject)
        if result is None:
            for parent in named_parents.get(subject, []):
                if parent not in seen and parent != D3F.DefensiveTechnique:
                    result = tactic_of(parent, seen | {subject})
                    if result:
                        break
        if not seen:
            tactic_cache[subject] = result
        return result

    def restrictions(subject: URIRef) -> list[dict]:
        out = []
        for node in graph.objects(subject, RDFS.subClassOf):
            if isinstance(node, BNode) and (node, RDF.type, OWL.Restriction) in graph:
                prop = graph.value(node, OWL.onProperty)
                value = graph.value(node, OWL.someValuesFrom)
                if prop is None or value is None or prop == D3F.enables or not isinstance(value, URIRef):
                    continue
                out.append({"rel": local_name(prop), "artifact": local_name(value)})
        return sorted(out, key=lambda r: (r["rel"], r["artifact"]))

    for subject, d3id in d3id_of.items():
        parents = [d3id_of[p] for p in named_parents.get(subject, []) if p in d3id_of]
        label = _text(graph, subject, RDFS.label) or local_name(subject)
        node_id = f"d3fend:{d3id}"
        # D3A-* IDs are D3FEND analytic techniques (methods such as clustering), not countermeasures.
        is_analytic = d3id.startswith("D3A-")
        tactic = None if is_analytic else tactic_of(subject)
        writer.add_node(
            node_id,
            framework="d3fend",
            kind="analytic-technique" if is_analytic else "countermeasure",
            ext_id=d3id,
            name=label,
            description=_text(graph, subject, D3F.definition),
            url=D3FEND_URL.format(local=local_name(subject)),
            domains=["d3fend"],
            deprecated=(subject, OWL.deprecated, Literal(True)) in graph,
            version=version,
            source=source_key,
            extra={
                "iri": f"d3f:{local_name(subject)}",
                "tactic": tactic,
                "parents": parents,
                "artifacts": restrictions(subject),
            },
        )
        for parent in parents:
            writer.add_edge(node_id, "child_of", f"d3fend:{parent}", source=source_key)
        if tactic:
            writer.add_edge(node_id, "enables", f"d3fend:{tactic}", source=source_key)

    # Digital artifacts (and events), for lookups and for typing CAD artifact nodes.
    artifact_roots = [D3F.DigitalArtifact, D3F.DigitalEvent]
    artifacts: set[URIRef] = set()
    queue = deque(r for r in artifact_roots if (r, None, None) in graph)
    while queue:
        current = queue.popleft()
        if current in artifacts:
            continue
        artifacts.add(current)
        queue.extend(children.get(current, []))
    for artifact in artifacts:
        if artifact in d3id_of:
            continue
        name = local_name(artifact)
        label = _text(graph, artifact, RDFS.label) or name
        writer.add_node(
            f"d3fend:artifact:{name}",
            framework="d3fend",
            kind="artifact",
            ext_id=name,
            name=label,
            description=_text(graph, artifact, D3F.definition),
            url=ARTIFACT_URL.format(local=name),
            domains=["d3fend"],
            version=version,
            source=source_key,
            extra={"iri": f"d3f:{name}", "parents": [local_name(p) for p in named_parents.get(artifact, [])]},
        )

    # Object property labels, so CAD edges can carry d3f properties.
    properties = {}
    for prop in graph.subjects(RDF.type, OWL.ObjectProperty):
        if isinstance(prop, URIRef) and str(prop).startswith(str(D3F)):
            properties[_text(graph, prop, RDFS.label) or local_name(prop)] = f"d3f:{local_name(prop)}"
    writer.d3fend_properties = properties  # type: ignore[attr-defined]
    # Offensive technique IDs the ontology knows (ATT&CK and ATLAS), so queries can tell
    # "D3FEND has not caught up to this technique yet" apart from "D3FEND maps nothing to it".
    writer.d3fend_known_offensive_ids = sorted(  # type: ignore[attr-defined]
        {str(v).strip() for v in graph.objects(None, D3F["attack-id"])}
        | {local_name(s) for s in graph.subjects(RDF.type, OWL.Class) if str(s).startswith(str(D3F) + "AML.")}
    )
    writer.d3fend_iri_to_id = {local_name(s): d for s, d in d3id_of.items()}  # type: ignore[attr-defined]
    writer.d3fend_label_to_id = {  # type: ignore[attr-defined]
        (_text(graph, s, RDFS.label) or "").lower(): d for s, d in d3id_of.items()
    }

    return {
        "source": source_key,
        "version": version,
        "nodes": len(d3id_of) + len(artifacts) + len(tactic_label),
        "techniques": len(d3id_of),
        "artifacts": len(artifacts),
        "tactics": len(tactic_label),
    }


def _rows(data) -> list[dict]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        bindings = (data.get("results") or {}).get("bindings")
        if bindings is not None:
            return bindings
    raise ValueError("unrecognized D3FEND mappings format: expected SPARQL JSON results or a list of rows")


def _cell(row: dict, key: str) -> str | None:
    value = row.get(key)
    if isinstance(value, dict):
        value = value.get("value")
    return value or None


def ingest_d3fend_mappings(writer: GraphWriter, path: Path, source_key: str = "d3fend-mappings") -> dict:
    rows = _rows(json.loads(Path(path).read_text(encoding="utf-8")))
    iri_to_id: dict[str, str] = getattr(writer, "d3fend_iri_to_id", {})
    label_to_id: dict[str, str] = getattr(writer, "d3fend_label_to_id", {})
    required = {"off_tech_id", "def_artifact_label", "off_artifact_label"}
    if rows:
        columns = set(rows[0])
        missing = required - columns
        if missing or not ({"def_tech", "def_tech_label"} & columns):
            raise ValueError(
                "D3FEND mappings format not recognized (missing columns "
                f"{sorted(missing) or ['def_tech/def_tech_label']}); the published format may have changed. "
                f"Columns seen: {sorted(columns)[:25]}"
            )
    used = 0
    skipped: dict[str, int] = defaultdict(int)
    for row in rows:
        off_id = _cell(row, "off_tech_id")
        if not off_id:
            skipped["no offensive technique id"] += 1
            continue
        if re.match(r"^T\d{4}(\.\d{3})?$", off_id):
            target = f"attack:{off_id}"
        elif off_id.startswith("AML."):
            target = f"atlas:{off_id}"
        else:
            skipped[f"unsupported offensive id prefix {off_id.split('-')[0][:8]}"] += 1
            continue
        def_local = local_name(_cell(row, "def_tech"))
        def_label = _cell(row, "def_tech_label") or ""
        d3id = iri_to_id.get(def_local or "") or label_to_id.get(def_label.lower())
        if not d3id:
            skipped["defensive technique not in ontology"] += 1
            continue
        path_detail = {
            "def_rel": _cell(row, "def_artifact_rel_label"),
            "def_rel_iri": local_name(_cell(row, "def_artifact_rel")),
            "def_artifact": _cell(row, "def_artifact_label"),
            "def_artifact_iri": local_name(_cell(row, "def_artifact")),
            "off_rel": _cell(row, "off_artifact_rel_label"),
            "off_rel_iri": local_name(_cell(row, "off_artifact_rel")),
            "off_artifact": _cell(row, "off_artifact_label"),
            "off_artifact_iri": local_name(_cell(row, "off_artifact")),
        }
        detail = {"paths": [{k: v for k, v in path_detail.items() if v}]}
        tactic = _cell(row, "def_tactic_label")
        if tactic:
            detail["tactic"] = tactic
        writer.add_edge(f"d3fend:{d3id}", "counters", target, source=source_key, detail=detail)
        used += 1
    if rows and used == 0:
        raise ValueError(f"D3FEND mappings: none of {len(rows)} rows could be used ({dict(skipped)})")
    unresolved = skipped.get("defensive technique not in ontology", 0)
    if rows and unresolved > 0.05 * len(rows):
        writer.warnings.append(
            f"{source_key}: {unresolved} of {len(rows)} rows name defensive techniques missing from the loaded "
            "ontology; the ontology and mappings may be from different D3FEND releases"
        )
    return {"source": source_key, "rows": len(rows), "used_rows": used, "skipped": dict(skipped)}
