"""Offline validation against vendored official schemas.

- Attack Flow 2.0 schema (CTID, Apache-2.0) plus the OASIS STIX 2.1 common schemas
  it references (OASIS cti-stix2-json-schemas, BSD-3-Clause), resolved locally.
- D3FEND CAD graph schema as published at https://d3fend.mitre.org/cad/docs/schema.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ATTACK_FLOW_EXTENSION_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
ATTACK_FLOW_SDOS = {"attack-flow", "attack-action", "attack-asset", "attack-condition", "attack-operator"}
_STIX_PREFIXES = (
    "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/",
    "https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/",
    "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/schemas/",
    "https://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/master/schemas/",
)


def _schema_file(*parts: str) -> dict[str, Any]:
    path = resources.files("countermap.emit").joinpath("schemas", *parts)
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _attack_flow_validator() -> jsonschema.Draft202012Validator:
    schema = _schema_file("attack-flow-schema-2.0.0.json")
    resources_ = []
    common_dir = resources.files("countermap.emit").joinpath("schemas", "stix2.1", "common")
    for entry in common_dir.iterdir():
        if entry.name.endswith(".json"):
            contents = json.loads(entry.read_text(encoding="utf-8"))
            resource = Resource.from_contents(contents, default_specification=DRAFT202012)
            for prefix in _STIX_PREFIXES:
                resources_.append((prefix + "common/" + entry.name, resource))
    registry = Registry().with_resources(resources_)
    return jsonschema.Draft202012Validator(schema, registry=registry)


@lru_cache(maxsize=1)
def _cad_validator() -> jsonschema.Draft7Validator:
    return jsonschema.Draft7Validator(_schema_file("d3fend-cad-schema.json"))


def validate_attack_flow(bundle: dict[str, Any]) -> list[str]:
    """Return a list of errors (empty when valid). Mirrors the CTID validator's structural checks."""
    errors = []
    if bundle.get("type") != "bundle":
        errors.append("top-level object must be a STIX bundle")
    if not str(bundle.get("id", "")).startswith("bundle--"):
        errors.append("bundle id must start with bundle--")
    objects = bundle.get("objects") or []
    if sum(1 for o in objects if o.get("type") == "attack-flow") != 1:
        errors.append("bundle must contain exactly one attack-flow object")
    if not any(o.get("type") == "extension-definition" and o.get("id") == ATTACK_FLOW_EXTENSION_ID for o in objects):
        errors.append("bundle must include the Attack Flow extension-definition")
    ids = {o.get("id") for o in objects}
    validator = _attack_flow_validator()
    for obj in objects:
        if obj.get("type") in ATTACK_FLOW_SDOS:
            for err in validator.iter_errors(obj):
                errors.append(f"{obj.get('id')}: {err.message}")
        for key in ("start_refs", "effect_refs", "asset_refs", "on_true_refs", "on_false_refs"):
            for ref in obj.get(key, []) or []:
                if ref not in ids:
                    errors.append(f"{obj.get('id')}: {key} points at undefined {ref}")
    return errors


def validate_cad(graph: dict[str, Any]) -> list[str]:
    errors = [f"{'/'.join(map(str, e.path)) or '(root)'}: {e.message}" for e in _cad_validator().iter_errors(graph)]
    node_ids = {n.get("id") for n in graph.get("nodes", [])}
    for edge in graph.get("edges", []):
        for end in ("source", "target"):
            if edge.get(end) not in node_ids:
                errors.append(f"edge {edge.get('id')}: {end} {edge.get(end)} is not a node")
    return errors
