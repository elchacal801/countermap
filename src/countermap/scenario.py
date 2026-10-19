"""The scenario spec: the single structure agents produce.

Agents never write CAD JSON, Attack Flow STIX or Navigator layers by hand. They
write a small scenario (ordered steps that reference technique IDs, optionally
countermeasures), and Countermap validates every ID against the loaded data and
renders all output formats from it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .query import Countermap, NotFound


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,40}$", description="Unique step id, e.g. s1")
    technique: str = Field(description="Technique ID: ATT&CK (T1566.001), ATLAS (AML.T0051), F3 (F1005 or f3:T1056)")
    name: str | None = Field(None, description="Optional label for this step; defaults to the technique name")
    description: str | None = Field(None, description="What happened in this step (observed or hypothesized)")
    after: list[str] = Field(default_factory=list, description="Ids of steps that precede this one")
    assets: list[str] = Field(default_factory=list, description="Assets touched by this step (free text)")


class CountermeasureRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(description="D3FEND technique ID, e.g. D3-FH")
    targets: list[str] = Field(min_length=1, description="Step ids this countermeasure applies to")


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    authors: list[str] = Field(default_factory=list)
    steps: list[Step] = Field(min_length=1, max_length=100)
    countermeasures: Literal["auto", "none"] | list[CountermeasureRef] = Field(
        "auto", description="'auto' picks official D3FEND countermeasures per step; or list them explicitly"
    )
    max_countermeasures_per_step: int = Field(3, ge=0, le=20)
    d3fend_tactics: list[str] | None = Field(None, description="Restrict auto countermeasures to these D3FEND tactics")

    @model_validator(mode="after")
    def _check_graph(self) -> "Scenario":
        for s in self.steps:
            s.after = list(dict.fromkeys(s.after))
            if s.id in s.after:
                raise ValueError(f"step {s.id} lists itself as a predecessor")
        if isinstance(self.countermeasures, list):
            for cm in self.countermeasures:
                cm.targets = list(dict.fromkeys(cm.targets))
        ids = [s.id for s in self.steps]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate step ids: {sorted(dupes)}")
        known = set(ids)
        for s in self.steps:
            missing = [a for a in s.after if a not in known]
            if missing:
                raise ValueError(f"step {s.id} refers to unknown predecessor(s) {missing}")
        if isinstance(self.countermeasures, list):
            for cm in self.countermeasures:
                missing = [t for t in cm.targets if t not in known]
                if missing:
                    raise ValueError(f"countermeasure {cm.id} targets unknown step(s) {missing}")
        # Cycle check (Kahn).
        indeg = {s.id: len(s.after) for s in self.steps}
        succ: dict[str, list[str]] = {s.id: [] for s in self.steps}
        for s in self.steps:
            for a in s.after:
                succ[a].append(s.id)
        ready = [i for i, d in indeg.items() if d == 0]
        seen = 0
        while ready:
            node = ready.pop()
            seen += 1
            for n in succ[node]:
                indeg[n] -= 1
                if indeg[n] == 0:
                    ready.append(n)
        if seen != len(self.steps):
            raise ValueError("step ordering contains a cycle")
        return self


@dataclass
class ResolvedStep:
    id: str
    node_id: str
    framework: str
    technique_id: str
    technique_name: str
    label: str
    description: str | None
    after: list[str]
    assets: list[str]
    tactics: list[dict]
    depth: int = 0
    url: str | None = None


@dataclass
class CounterLink:
    step_id: str
    d3fend_id: str
    d3fend_name: str
    d3fend_iri: str | None
    tactic: str | None
    provenance: str
    via: str | None
    path: dict[str, Any] | None


@dataclass
class ResolvedScenario:
    title: str
    description: str
    authors: list[str]
    steps: list[ResolvedStep]
    links: list[CounterLink] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    omitted: dict[str, int] = field(default_factory=dict)
    versions: dict[str, Any] = field(default_factory=dict)
    d3fend_properties: dict[str, str] = field(default_factory=dict)
    artifact_iris: dict[str, str] = field(default_factory=dict)
    d3fend_known_ids: set[str] = field(default_factory=set)



# Order used when picking countermeasures for diagrams: actionable tactics first, Model last.
AUTO_TACTIC_ORDER = ["Harden", "Detect", "Isolate", "Evict", "Restore", "Deceive", "Model"]


def _pick_diverse(cms: list[dict], limit: int) -> list[dict]:
    """Pick up to ``limit`` countermeasures, official before derived, one tactic at a time (round-robin)."""
    def rank(m: dict) -> tuple:
        tactic = m.get("tactic") or ""
        # Within a tactic, prefer countermeasures that act on the same artifact the attack touches
        # (a direct path) over ones linked through the artifact class hierarchy.
        return (m["provenance"] != "official",
                AUTO_TACTIC_ORDER.index(tactic) if tactic in AUTO_TACTIC_ORDER else 99,
                _direct_path(m) is None, m["name"])

    buckets: dict[str, list[dict]] = {}
    for m in sorted(cms, key=rank):
        buckets.setdefault(m.get("tactic") or "unknown", []).append(m)
    order = sorted(buckets, key=lambda t: min(rank(m) for m in buckets[t]))
    chosen: list[dict] = []
    while len(chosen) < limit and any(buckets.values()):
        for tactic in order:
            if buckets[tactic] and len(chosen) < limit:
                chosen.append(buckets[tactic].pop(0))
    return chosen


def _direct_path(m: dict) -> dict | None:
    return next((p for p in m.get("paths", []) if p.get("def_artifact") and p.get("def_artifact") == p.get("off_artifact")), None)


def _best_path(m: dict) -> dict | None:
    return _direct_path(m) or (m["paths"][0] if m.get("paths") else None)


def _extra(row) -> dict:
    return json.loads(row["extra"] or "{}") if row is not None else {}


def _technique_ref(c: Countermap, ref: str) -> tuple[str, list[str]]:
    node_id, warnings, _ = c._technique(ref)
    return node_id, warnings


def resolve_scenario(spec: Scenario | dict, c: Countermap) -> ResolvedScenario:
    scenario = spec if isinstance(spec, Scenario) else Scenario.model_validate(spec)
    warnings: list[str] = []
    errors: list[str] = []
    steps: list[ResolvedStep] = []
    for s in scenario.steps:
        try:
            node_id, notes = _technique_ref(c, s.technique)
        except NotFound as exc:
            errors.append(f"step {s.id}: {exc}")
            continue
        warnings.extend(f"step {s.id}: {n}" for n in notes)
        row = c._node(node_id)
        steps.append(ResolvedStep(
            id=s.id, node_id=node_id, framework=row["framework"], technique_id=row["ext_id"],
            technique_name=row["name"], label=s.name or row["name"], description=s.description,
            after=list(s.after), assets=list(s.assets), tactics=c._tactics(node_id), url=row["url"],
        ))
    if errors:
        raise NotFound("; ".join(errors))

    # Layered depth for layout: longest path from a root (the spec is validated acyclic).
    by_id = {s.id: s for s in steps}
    changed = True
    while changed:
        changed = False
        for s in steps:
            depth = max((by_id[a].depth + 1 for a in s.after), default=0)
            if depth != s.depth:
                s.depth = depth
                changed = True

    resolved = ResolvedScenario(
        title=scenario.title, description=scenario.description, authors=scenario.authors, steps=steps,
        warnings=warnings, versions=c.source_versions(),
        d3fend_properties=c.meta("d3fend_properties", {}) or {},
        d3fend_known_ids=set(c.meta("d3fend_known_offensive_ids", []) or []),
    )
    resolved.artifact_iris = {
        r["name"].lower(): _extra(r).get("iri")
        for r in c.conn.execute("SELECT name, extra FROM nodes WHERE framework = 'd3fend' AND kind = 'artifact'")
    }

    if scenario.countermeasures == "none":
        return resolved
    if scenario.countermeasures == "auto" and scenario.max_countermeasures_per_step == 0:
        return resolved

    tactics = {t.lower() for t in scenario.d3fend_tactics} if scenario.d3fend_tactics else None
    if scenario.countermeasures == "auto":
        if c._mapping_status() != "loaded":
            resolved.warnings.append("D3FEND published mappings are not loaded; no countermeasures were added.")
            return resolved
        for s in steps:
            cms = c.countermeasures(s.node_id, limit=200)["countermeasures"]
            if tactics:
                cms = [m for m in cms if (m["tactic"] or "").lower() in tactics]
            chosen = _pick_diverse(cms, scenario.max_countermeasures_per_step)
            if len(cms) > len(chosen):
                resolved.omitted[s.id] = len(cms) - len(chosen)
            for m in chosen:
                row = c._node(f"d3fend:{m['d3fend_id']}")
                iri = _extra(row).get("iri")
                resolved.links.append(CounterLink(
                    step_id=s.id, d3fend_id=m["d3fend_id"], d3fend_name=m["name"], d3fend_iri=iri,
                    tactic=m["tactic"], provenance=m["provenance"], via=m["via"],
                    path=_best_path(m),
                ))
        return resolved

    for ref in scenario.countermeasures:
        try:
            cm_id = c.parse_ref(ref.id, framework="d3fend")
        except NotFound as exc:
            raise NotFound(f"countermeasure {ref.id}: {exc}") from exc
        row = c._node(cm_id)
        if row["kind"] != "countermeasure":
            raise NotFound(f"countermeasure {ref.id}: {cm_id} is a D3FEND {row['kind']}, not a countermeasure technique")
        iri = _extra(row).get("iri")
        for target in ref.targets:
            step = by_id[target]
            match = next((m for m in c.countermeasures(step.node_id, limit=200)["countermeasures"]
                          if m["d3fend_id"] == row["ext_id"]), None)
            if match is None:
                resolved.warnings.append(
                    f"{row['ext_id']} is not mapped to {step.technique_id} in D3FEND's published mappings; drawn as an analyst assertion"
                )
            resolved.links.append(CounterLink(
                step_id=target, d3fend_id=row["ext_id"], d3fend_name=row["name"], d3fend_iri=iri,
                tactic=(match or {}).get("tactic") or _extra(row).get("tactic"),
                provenance=(match or {}).get("provenance", "analyst"), via=(match or {}).get("via"),
                path=_best_path(match) if match else None,
            ))
    return resolved
