"""Compare two Countermap snapshots (for example ATT&CK v19.2 vs v20.0)."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from .db import connect


def _loaded_sources(path: Path) -> set[str]:
    conn = connect(path, read_only=True)
    keys = {r["key"] for r in conn.execute("SELECT key FROM sources WHERE status = 'loaded'")}
    conn.close()
    return keys


def _load(path: Path, framework: str | None, datasets: set[str]):
    conn = connect(path, read_only=True)
    sql = "SELECT id, framework, kind, ext_id, name, description, deprecated, revoked, source FROM nodes"
    params: list[Any] = []
    if framework:
        sql += " WHERE framework = ?"
        params.append(framework)
    # Only compare objects from datasets loaded in both snapshots, so a snapshot that
    # lacks Mobile or ICS does not show their objects as "added".
    nodes = {r["id"]: dict(r) for r in conn.execute(sql, params) if r["source"] in datasets}
    tactics: dict[str, set[str]] = defaultdict(set)
    revoked_by: dict[str, list[str]] = defaultdict(list)
    for e in conn.execute("SELECT src, rel, dst FROM edges WHERE rel IN ('in_tactic', 'revoked_by')"):
        if e["src"] in nodes:
            if e["rel"] == "in_tactic":
                tactics[e["src"]].add(e["dst"])
            else:
                revoked_by[e["src"]].append(e["dst"])
    versions = {r["key"]: r["version"] for r in conn.execute("SELECT key, version FROM sources")}
    conn.close()
    return nodes, tactics, revoked_by, versions


def diff_snapshots(old_path: Path, new_path: Path, framework: str | None = "attack",
                   kind: str | None = None, limit: int = 50) -> dict[str, Any]:
    common = _loaded_sources(Path(old_path)) & _loaded_sources(Path(new_path))
    old, old_tac, _, old_v = _load(Path(old_path), framework, common)
    new, new_tac, new_rev, new_v = _load(Path(new_path), framework, common)

    def keep(n: dict) -> bool:
        return kind is None or n["kind"] == kind

    def label(n: dict) -> str:
        return f"{n['ext_id']} {n['name']}"

    added = [label(new[i]) for i in sorted(new.keys() - old.keys()) if keep(new[i])]
    removed = [label(old[i]) for i in sorted(old.keys() - new.keys()) if keep(old[i])]
    renamed, newly_revoked, newly_deprecated, tactic_changed, description_changed = [], [], [], [], []
    for i in sorted(old.keys() & new.keys()):
        a, b = old[i], new[i]
        if not keep(b):
            continue
        if b["revoked"] and not a["revoked"]:
            newly_revoked.append({"id": b["ext_id"], "name": b["name"], "replaced_by": [
                label(new[r]) if r in new else r for r in new_rev.get(i, [])]})
            continue
        if b["deprecated"] and not a["deprecated"]:
            newly_deprecated.append(label(b))
            continue
        if a["name"] != b["name"]:
            renamed.append({"id": b["ext_id"], "old": a["name"], "new": b["name"]})
        if old_tac.get(i, set()) != new_tac.get(i, set()):
            tactic_changed.append({
                "id": b["ext_id"], "name": b["name"],
                "removed": sorted(old_tac.get(i, set()) - new_tac.get(i, set())),
                "added": sorted(new_tac.get(i, set()) - old_tac.get(i, set())),
            })
        if (a["description"] or "") != (b["description"] or ""):
            description_changed.append(b["ext_id"])

    def cap(items: list) -> dict:
        return {"count": len(items), "items": items[:limit]}

    return {
        "framework": framework,
        "kind": kind,
        "compared_datasets": sorted(common),
        "old_versions": old_v,
        "new_versions": new_v,
        "added": cap(added),
        "removed": cap(removed),
        "newly_revoked": cap(newly_revoked),
        "newly_deprecated": cap(newly_deprecated),
        "renamed": cap(renamed),
        "tactic_changed": cap(tactic_changed),
        "description_changed": cap(description_changed),
    }
