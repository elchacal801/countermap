"""SQLite storage for the cross-framework graph.

Design rules:
- Every node belongs to exactly one framework namespace ("attack:T1003", "f3:T1056").
  F3 and ATLAS reuse or reference ATT&CK IDs, but their objects carry their own
  definitions, so they are never merged with ATT&CK nodes.
- Every stored edge records its provenance and the dataset it came from. Stored
  edges are always "official" (taken directly from an upstream publication).
  "Derived" links are composed at query time and always carry the path they
  were derived through.
"""

from __future__ import annotations

import json
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 1

DDL = """
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE sources (
  key          TEXT PRIMARY KEY,
  framework    TEXT NOT NULL,
  title        TEXT NOT NULL,
  version      TEXT,
  url          TEXT,
  sha256       TEXT,
  license      TEXT,
  retrieved_at TEXT,
  status       TEXT NOT NULL,
  note         TEXT
);
CREATE TABLE nodes (
  id          TEXT PRIMARY KEY,
  framework   TEXT NOT NULL,
  kind        TEXT NOT NULL,
  ext_id      TEXT NOT NULL,
  name        TEXT NOT NULL,
  description TEXT,
  url         TEXT,
  domains     TEXT,
  platforms   TEXT,
  aliases     TEXT,
  deprecated  INTEGER NOT NULL DEFAULT 0,
  revoked     INTEGER NOT NULL DEFAULT 0,
  version     TEXT,
  modified    TEXT,
  stix_id     TEXT,
  source      TEXT NOT NULL,
  extra       TEXT
);
CREATE INDEX nodes_ext  ON nodes(ext_id);
CREATE INDEX nodes_kind ON nodes(framework, kind);
CREATE INDEX nodes_name ON nodes(name COLLATE NOCASE);
CREATE TABLE edges (
  src        TEXT NOT NULL,
  rel        TEXT NOT NULL,
  dst        TEXT NOT NULL,
  provenance TEXT NOT NULL CHECK (provenance IN ('official', 'derived')),
  source     TEXT NOT NULL,
  detail     TEXT
);
CREATE INDEX edges_src ON edges(src, rel);
CREATE INDEX edges_dst ON edges(dst, rel);
CREATE UNIQUE INDEX edges_unique ON edges(src, rel, dst, source);
CREATE VIRTUAL TABLE nodes_fts USING fts5(
  id UNINDEXED, ext_id, name, aliases, description,
  tokenize = 'porter unicode61'
);
"""

# Normalized relationship vocabulary. Documented here so tools and agents can rely on it.
RELATIONS = {
    "uses": "group/software/campaign uses technique; group/campaign uses software",
    "mitigates": "mitigation mitigates technique",
    "detects": "ATT&CK detection strategy detects technique",
    "has_analytic": "detection strategy contains analytic",
    "uses_data_component": "analytic relies on data component (detail: log source name/channel)",
    "part_of_data_source": "data component belongs to data source",
    "subtechnique_of": "sub-technique of parent technique",
    "revoked_by": "object revoked and replaced by another object",
    "attributed_to": "campaign attributed to group",
    "targets": "ATT&CK ICS technique targets an asset",
    "in_tactic": "technique belongs to tactic",
    "employs": "ATLAS case study employs technique (detail: step, tactic, sequence)",
    "references_attack": "ATLAS technique references an ATT&CK technique (official ATLAS crosswalk)",
    "reuses_attack_id": "F3 object reuses an ATT&CK ID with an F3-specific definition",
    "counters": "D3FEND countermeasure counters an offensive technique (MITRE's published D3FEND inference; detail: artifact paths)",
    "child_of": "D3FEND technique specializes a parent D3FEND technique",
    "enables": "D3FEND technique enables a D3FEND tactic",
}


def connect(path: str | Path, read_only: bool = False) -> sqlite3.Connection:
    path = Path(path)
    if read_only:
        # Percent-encode the path so '#', '?' or '%' in directory names cannot truncate the URI.
        uri = "file:" + urllib.parse.quote(path.resolve().as_posix()) + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    else:
        conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def dumps(value: Any) -> str | None:
    if value is None or value == [] or value == {}:
        return None
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def loads(value: str | None, default: Any = None) -> Any:
    if not value:
        return default
    return json.loads(value)


class GraphWriter:
    """Accumulates nodes and edges, then writes them in one transaction."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.exists():
            self.path.unlink()
        self.conn = connect(self.path)
        self.conn.executescript(DDL)
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self.sources: dict[str, dict[str, Any]] = {}
        self.warnings: list[str] = []

    # -- nodes -------------------------------------------------------------
    def add_node(
        self,
        node_id: str,
        *,
        framework: str,
        kind: str,
        ext_id: str,
        name: str,
        source: str,
        description: str | None = None,
        url: str | None = None,
        domains: Iterable[str] | None = None,
        platforms: Iterable[str] | None = None,
        aliases: Iterable[str] | None = None,
        deprecated: bool = False,
        revoked: bool = False,
        version: str | None = None,
        modified: str | None = None,
        stix_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        existing = self.nodes.get(node_id)
        if existing is not None and (existing["kind"] != kind or (
                existing["stix_id"] and stix_id and existing["stix_id"] != stix_id)):
            raise ValueError(
                f"ID collision on {node_id}: {existing['kind']} {existing['stix_id']} vs {kind} {stix_id}"
            )
        if existing is not None:
            # Same object published in several ATT&CK domains: merge domain/platform lists.
            for key, values in (("domains", domains), ("platforms", platforms), ("aliases", aliases)):
                merged = list(dict.fromkeys([*(existing[key] or []), *(values or [])]))
                existing[key] = merged
            if extra:
                existing["extra"] = {**(existing["extra"] or {}), **extra}
            return
        self.nodes[node_id] = {
            "id": node_id,
            "framework": framework,
            "kind": kind,
            "ext_id": ext_id,
            "name": name,
            "description": description,
            "url": url,
            "domains": list(dict.fromkeys(domains or [])),
            "platforms": list(dict.fromkeys(platforms or [])),
            "aliases": list(dict.fromkeys(a for a in (aliases or []) if a and a != name)),
            "deprecated": int(bool(deprecated)),
            "revoked": int(bool(revoked)),
            "version": version,
            "modified": modified,
            "stix_id": stix_id,
            "source": source,
            "extra": extra or {},
        }

    def has_node(self, node_id: str) -> bool:
        return node_id in self.nodes

    # -- edges -------------------------------------------------------------
    def add_edge(
        self,
        src: str,
        rel: str,
        dst: str,
        *,
        source: str,
        detail: dict[str, Any] | None = None,
        provenance: str = "official",
    ) -> None:
        if rel not in RELATIONS:
            raise ValueError(f"unknown relation {rel!r}")
        key = (src, rel, dst, source)
        if key in self.edges:
            if detail:
                current = self.edges[key]["detail"] or {}
                for k, v in detail.items():
                    if isinstance(v, list):
                        current.setdefault(k, [])
                        for item in v:
                            if item not in current[k]:
                                current[k].append(item)
                    else:
                        current.setdefault(k, v)
                self.edges[key]["detail"] = current
            return
        self.edges[key] = {
            "src": src,
            "rel": rel,
            "dst": dst,
            "provenance": provenance,
            "source": source,
            "detail": dict(detail) if detail else None,
        }

    # -- sources -----------------------------------------------------------
    def add_source(self, key: str, **fields: Any) -> None:
        self.sources[key] = {"key": key, **fields}

    # -- finalize ----------------------------------------------------------
    def commit(self, meta: dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.executemany(
            "INSERT INTO nodes (id, framework, kind, ext_id, name, description, url, domains, platforms,"
            " aliases, deprecated, revoked, version, modified, stix_id, source, extra)"
            " VALUES (:id, :framework, :kind, :ext_id, :name, :description, :url, :domains, :platforms,"
            " :aliases, :deprecated, :revoked, :version, :modified, :stix_id, :source, :extra)",
            [
                {
                    **n,
                    "domains": dumps(n["domains"]),
                    "platforms": dumps(n["platforms"]),
                    "aliases": dumps(n["aliases"]),
                    "extra": dumps(n["extra"]),
                }
                for n in self.nodes.values()
            ],
        )
        cur.executemany(
            "INSERT INTO edges (src, rel, dst, provenance, source, detail)"
            " VALUES (:src, :rel, :dst, :provenance, :source, :detail)",
            [{**e, "detail": dumps(e["detail"])} for e in self.edges.values()],
        )
        cur.executemany(
            "INSERT INTO nodes_fts (id, ext_id, name, aliases, description) VALUES (?, ?, ?, ?, ?)",
            [
                (n["id"], n["ext_id"], n["name"], " ".join(n["aliases"]), (n["description"] or "")[:4000])
                for n in self.nodes.values()
            ],
        )
        cols = ("framework", "title", "version", "url", "sha256", "license", "retrieved_at", "status", "note")
        cur.executemany(
            "INSERT INTO sources (key, " + ", ".join(cols) + ") VALUES (:key, " + ", ".join(":" + c for c in cols) + ")",
            [{c: s.get(c) for c in ("key", *cols)} for s in self.sources.values()],
        )
        meta = {**meta, "schema_version": SCHEMA_VERSION, "warnings": self.warnings}
        cur.executemany(
            "INSERT INTO meta (key, value) VALUES (?, ?)",
            [(k, json.dumps(v)) for k, v in meta.items()],
        )
        self.conn.commit()
        self.conn.execute("VACUUM")
        self.conn.close()
