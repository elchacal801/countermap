"""Read-only query layer over a Countermap database.

All methods return plain JSON-serializable dicts. Every cross-framework result
carries ``provenance`` ("official" or "derived") and, for derived results, the
``via`` path it was composed through.
"""

from __future__ import annotations

import difflib
import json
import re
import sqlite3
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .db import connect, loads

PATTERNS = [
    (re.compile(r"^AML\.(TA|T|M|CS)\d{4}(\.\d{3})?$"), "atlas"),
    (re.compile(r"^F[AT]?\d{4}(\.\d{3})?$"), "f3"),
    (re.compile(r"^D3A?-[A-Z0-9-]+$"), "d3fend"),
    (re.compile(r"^(T\d{4}(\.\d{3})?|TA\d{4}|G\d{4}|S\d{4}|C\d{4}|M\d{4}|DET\d{4}|AN\d{4}|DC\d{4}|DS\d{4}|A\d{4})$"), "attack"),
]
FRAMEWORKS = ("attack", "f3", "atlas", "d3fend")
TACTIC_ORDER_D3FEND = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]
MAX_REF_CHARS = 200
MAX_LIST_ITEMS = 300

TELEMETRY_CLASSES = ("covered", "partial", "blind", "no_analytic_for_platform", "no_detection_strategy")
TELEMETRY_BASIS = (
    "computed by Countermap from MITRE's analytic log-source references. A technique is covered when at least one "
    "of its ATT&CK analytics (on the platform, if given) lists only log sources or data components you collect, "
    "partial when an analytic uses some of them, and blind when none does. The detection strategies, analytics, "
    "log sources and data components are MITRE's; the matching and the classes are Countermap's. Covered means the "
    "telemetry an analytic needs is collected, not that a rule exists or would fire."
)
TELEMETRY_SCORES = {"covered": 2, "partial": 1, "blind": 0}
RULE_SCORES = {"covered": 2, "partial": 1, "uncovered": 0}
RULE_BASIS = (
    "group counts are the groups ATT&CK links to the technique directly, or through software they use (the latter "
    "derived by Countermap), from MITRE's 'uses' relationships, not prevalence in the wild; the status and ranking "
    "are computed by Countermap"
)
RULE_COUNTING = (
    "A group counts once for a technique it uses directly or through software it uses (the ATT&CK 'uses' "
    "relationships that actor_techniques follows with include_software). groups.direct counts only the groups "
    "ATT&CK links to the technique itself, and each example says direct or derived; the ranking uses the total. "
    "Campaigns, the tie-break after groups, are counted the same way. With scope_actors, the ranking counts those "
    "actors first, then all groups, then campaigns, then the technique ID."
)
ATTACK_DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
MAX_RULE_TECHNIQUES = 2000
MAX_SCOPE_ACTORS = 50
MAX_TACTICS = 50
_EVENT_CODES = re.compile(r"^eventcode\s*=\s*(\d+(?:\s*,\s*\d+)*)$")
_ANALYTICS_PER_TECHNIQUE = 5
_WARNINGS_PER_KIND = 20


def _distinct(items: Iterable[Any] | None) -> list[str]:
    """Inputs with whitespace normalized, empties dropped and repeats (ignoring case) taken once, in order.

    Done before any cap, so repeated entries never push a distinct one past it.
    """
    seen: set[str] = set()
    out: list[str] = []
    for item in items or []:
        text = " ".join(str(item)[:4 * MAX_REF_CHARS].split())[:MAX_REF_CHARS]
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
    return out


def _capped(items: list[str], cap: int, notes: list[str], message: str) -> list[str]:
    """The first ``cap`` items, noting the cut (``message`` takes {cap} and {n}) when there is one."""
    if len(items) > cap:
        notes.append(message.format(cap=cap, n=len(items)))
    return items[:cap]


def _norm(text: str | None) -> str:
    return " ".join((text or "").split()).lower()


def _norm_channel(channel: str | None) -> str | None:
    """A comparable channel; MITRE writes "None" for a log source with no particular channel."""
    channel = _norm(channel)
    return None if channel in ("", "none") else channel


def _event_codes(channel: str | None) -> set[int] | None:
    """The codes in a channel such as "EventCode=4663, 4656", or None for any other kind of channel."""
    m = _EVENT_CODES.match(channel or "")
    return {int(x) for x in re.findall(r"\d+", m.group(1))} if m else None


def _split_log_source(raw: str, known: dict[str, str]) -> tuple[str, str | None]:
    """Split "WinEventLog:Sysmon EventCode=10" into a log source name and a channel.

    Names can contain spaces ("Network Traffic"), so the longest known name that starts the text wins;
    an unknown name is split at its first space.
    """
    text = " ".join(str(raw).split())
    key = text.lower()
    if key in known:
        return known[key], None
    prefix = max((k for k in known if key.startswith(k + " ")), key=len, default=None)
    if prefix:
        return known[prefix], text[len(prefix):].strip() or None
    name, _, channel = text.partition(" ")
    return name, channel or None


class NotFound(LookupError):
    pass


class Countermap:
    """Thread-safe: each thread gets its own read-only SQLite connection (MCP runs tools in worker threads)."""

    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        if not self.path.exists():
            raise FileNotFoundError(
                f"No Countermap database at {self.path}. Run `countermap build` first."
            )
        self._local = threading.local()
        self.conn  # open once now so a bad file fails here, not inside a tool call

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = connect(self.path, read_only=True)
            self._local.conn = conn
        return conn

    # -- primitives --------------------------------------------------------
    def _node(self, node_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()

    def _edges(self, *, src: str | None = None, dst: str | None = None, rel: str | None = None) -> list[sqlite3.Row]:
        clauses, params = [], []
        for col, val in (("src", src), ("dst", dst), ("rel", rel)):
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        return self.conn.execute("SELECT * FROM edges WHERE " + " AND ".join(clauses), params).fetchall()

    def meta(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def source_versions(self) -> dict[str, str | None]:
        return {r["key"]: r["version"] for r in self.conn.execute("SELECT key, version FROM sources WHERE status = 'loaded'")}

    def summarize(self, row: sqlite3.Row | None, desc_chars: int = 0) -> dict[str, Any]:
        if row is None:
            return {}
        out = {
            "id": row["id"],
            "framework": row["framework"],
            "kind": row["kind"],
            "ext_id": row["ext_id"],
            "name": row["name"],
            "url": row["url"],
        }
        if row["revoked"]:
            out["revoked"] = True
        if row["deprecated"]:
            out["deprecated"] = True
        if desc_chars and row["description"]:
            desc = row["description"]
            out["description"] = desc if len(desc) <= desc_chars else desc[: desc_chars - 1].rstrip() + "…"
        return out

    # -- id handling -------------------------------------------------------
    def parse_ref(self, ref: str, framework: str | None = None, kind: str | None = None) -> str:
        """Turn a user-supplied reference (ID, namespaced ID, name or alias) into a node id."""
        return self._parse(ref, framework=framework, kind=kind)[0]

    def _parse(self, ref: str, framework: str | None = None, kind: str | None = None) -> tuple[str, list[str]]:
        ref = (ref or "").strip()
        if not ref:
            raise NotFound("empty reference")
        if len(ref) > MAX_REF_CHARS:
            raise NotFound(f"reference longer than {MAX_REF_CHARS} characters")
        if framework is not None and framework not in FRAMEWORKS:
            raise NotFound(f"unknown framework {framework!r}; choose from {', '.join(FRAMEWORKS)}")
        if ":" in ref and ref.split(":", 1)[0] in FRAMEWORKS:
            if self._node(ref) is None:
                raise NotFound(f"{ref} is not in the loaded data")
            return ref, []
        upper = ref.upper()
        for pattern, fw in PATTERNS:
            if pattern.match(upper):
                candidate = f"{framework or fw}:{upper}"
                if self._node(candidate):
                    return candidate, []
                if fw == "attack" and framework is None and self._node(f"f3:{upper}"):
                    # F3 also uses ATT&CK-style IDs; fall back when ATT&CK lacks it.
                    return f"f3:{upper}", [f"{upper} is not in ATT&CK; using F3's {upper}"]
                raise NotFound(f"{ref} is not in the loaded data ({framework or fw})")
        # Name or alias. Prefer active objects, then ATT&CK > F3 > ATLAS > D3FEND, and say so when ambiguous.
        params: list[Any] = [ref]
        sql = "SELECT id, framework, kind, revoked, deprecated FROM nodes WHERE name = ? COLLATE NOCASE"
        if framework:
            sql += " AND framework = ?"
            params.append(framework)
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        rows = self.conn.execute(sql, params).fetchall()
        if not rows:
            sql = "SELECT id, framework, kind, revoked, deprecated, aliases FROM nodes WHERE instr(lower(aliases), ?) > 0"
            params = [json.dumps(ref.lower(), ensure_ascii=False)]
            if framework:
                sql += " AND framework = ?"
                params.append(framework)
            if kind:
                sql += " AND kind = ?"
                params.append(kind)
            rows = [r for r in self.conn.execute(sql, params)
                    if any(a.lower() == ref.lower() for a in loads(r["aliases"], []))]
        if not rows:
            suggestions = [s["id"] for s in self.search(ref, framework=framework, kind=kind, limit=5)["results"]]
            raise NotFound(f"{ref!r} not found" + (f"; did you mean {', '.join(suggestions)}?" if suggestions else ""))
        rows = sorted(rows, key=lambda r: (r["revoked"], r["deprecated"], FRAMEWORKS.index(r["framework"]), r["id"]))
        warnings = []
        active = [r for r in rows if not r["revoked"] and not r["deprecated"]]
        if len(active) > 1:
            others = ", ".join(r["id"] for r in active[1:6])
            warnings.append(
                f"{ref!r} matches {len(active)} objects; using {rows[0]['id']} (also: {others}). "
                "Pass an ID or a framework to be explicit."
            )
        return rows[0]["id"], warnings

    def resolve(self, node_id: str) -> dict[str, Any]:
        """Follow revoked-by chains to the current object."""
        chain = [node_id]
        current = node_id
        for _ in range(10):
            row = self._node(current)
            if row is None or not row["revoked"]:
                break
            nxt = [e["dst"] for e in self._edges(src=current, rel="revoked_by")]
            if not nxt:
                break
            current = nxt[0]
            chain.append(current)
        return {"id": current, "chain": chain, "changed": current != node_id}

    def _ref_resolved(self, ref: str, framework: str | None = None, kind: str | None = None) -> tuple[str, list[str]]:
        node_id, warnings = self._parse(ref, framework=framework, kind=kind)
        res = self.resolve(node_id)
        if res["changed"]:
            warnings.append(f"{node_id} is revoked; using {res['id']} (chain: {' -> '.join(res['chain'])})")
        row = self._node(res["id"])
        if row is not None and row["deprecated"]:
            warnings.append(f"{res['id']} is deprecated in the loaded data")
        return res["id"], warnings

    def _technique(self, ref: str) -> tuple[str, list[str], sqlite3.Row]:
        node_id, warnings = self._ref_resolved(ref, kind=None)
        row = self._node(node_id)
        if row["kind"] != "technique":
            # A name may match a non-technique first (e.g. a software named like a technique); retry by kind.
            try:
                node_id, warnings = self._ref_resolved(ref, kind="technique")
                row = self._node(node_id)
            except NotFound:
                pass
        if row["kind"] != "technique":
            raise NotFound(f"{ref} resolves to {row['id']}, a {row['kind']}, not a technique")
        return node_id, warnings, row

    # -- tools -------------------------------------------------------------
    def datasets(self) -> dict[str, Any]:
        sources = [dict(r) for r in self.conn.execute("SELECT * FROM sources ORDER BY key")]
        counts = defaultdict(dict)
        for r in self.conn.execute(
            "SELECT framework, kind, COUNT(*) AS n FROM nodes WHERE revoked = 0 AND deprecated = 0 GROUP BY framework, kind"
        ):
            counts[r["framework"]][r["kind"]] = r["n"]
        edge_counts = {
            f"{r['source']}:{r['rel']}": r["n"]
            for r in self.conn.execute("SELECT source, rel, COUNT(*) AS n FROM edges GROUP BY source, rel")
        }
        return {
            "built_at": self.meta("built_at"),
            "sources": sources,
            "active_object_counts": counts,
            "edge_counts": edge_counts,
            "warnings": self.meta("warnings", []),
            "notes": [
                "Stored links are official (published by MITRE). Derived links are composed at query time and always show their path.",
                "D3FEND countermeasure links come only from MITRE's published D3FEND inference output.",
            ],
        }

    def search(self, query: str, framework: str | None = None, kind: str | None = None,
               limit: int = 10, include_inactive: bool = False) -> dict[str, Any]:
        query = (query or "")[:500]
        terms = re.findall(r"[\w.\-]+", query)[:20]
        if not terms:
            return {"query": query, "results": []}
        fts = " ".join('"' + t.replace('"', "") + '"' + ("*" if i == len(terms) - 1 else "") for i, t in enumerate(terms))
        sql = (
            "SELECT n.*, bm25(nodes_fts, 0.0, 10.0, 5.0, 3.0, 1.0) AS score FROM nodes_fts"
            " JOIN nodes n ON n.id = nodes_fts.id WHERE nodes_fts MATCH ?"
        )
        params: list[Any] = [fts]
        if framework:
            sql += " AND n.framework = ?"
            params.append(framework)
        if kind:
            sql += " AND n.kind = ?"
            params.append(kind)
        if not include_inactive:
            sql += " AND n.revoked = 0 AND n.deprecated = 0"
        sql += " ORDER BY score LIMIT ?"
        params.append(max(1, min(int(limit), 50)))
        try:
            rows = self.conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            rows = []
        return {"query": query, "results": [self.summarize(r, desc_chars=160) for r in rows]}

    def lookup(self, ref: str, framework: str | None = None, desc_chars: int = 1200) -> dict[str, Any]:
        node_id, warnings = self._ref_resolved(ref, framework=framework)
        row = self._node(node_id)
        out = self.summarize(row, desc_chars=desc_chars)
        out["domains"] = loads(row["domains"], [])
        out["platforms"] = loads(row["platforms"], [])
        if row["aliases"]:
            out["aliases"] = loads(row["aliases"], [])
        extra = loads(row["extra"], {})
        for key in ("tactic", "parents", "artifacts", "software_type", "maturity", "iri", "log_sources",
                    "mutable_elements", "first_seen", "last_seen", "first_seen_citation", "last_seen_citation"):
            if key in extra:
                out[key] = extra[key]
        if row["framework"] == "attack":
            out.update(self._detection_detail(row))
        out["source"] = {"dataset": row["source"], "version": self.source_versions().get(row["source"])}
        out["relations"] = self._relation_summary(node_id)
        if warnings:
            out["warnings"] = warnings
        return out

    def _detection_detail(self, row: sqlite3.Row, limit: int = 15) -> dict[str, Any]:
        """What ``lookup`` adds for ATT&CK detection objects, beyond the relation summary.

        A detection strategy gets its analytics with platforms and log sources. An analytic gets its strategy
        with the techniques that strategy detects, and its log sources with their data components. A data
        component gets the analytics that use it and the techniques their strategies detect, capped at ``limit``.
        """
        def under(rel: str, node_id: str) -> list[sqlite3.Row]:
            return self._active(dict.fromkeys(e["dst"] for e in self._edges(src=node_id, rel=rel)))

        def over(rel: str, node_id: str) -> list[sqlite3.Row]:
            return self._active(dict.fromkeys(e["src"] for e in self._edges(dst=node_id, rel=rel)))

        out: dict[str, Any] = {}
        if row["kind"] == "detection-strategy":
            out["analytics"] = [{"id": an["ext_id"], "platforms": loads(an["platforms"], []),
                                 "log_sources": self._analytic_log_sources(an["id"])}
                                for an in under("has_analytic", row["id"])]
        elif row["kind"] == "analytic":
            out["detection_strategies"] = [
                {"id": ds["ext_id"], "name": ds["name"],
                 "detects": [f"{t['ext_id']} {t['name']}" for t in under("detects", ds["id"])]}
                for ds in over("has_analytic", row["id"])]
            out["log_sources"] = self._analytic_log_sources(row["id"])
        elif row["kind"] == "data-component":
            analytics, techniques = [], {}
            for an in over("uses_data_component", row["id"]):
                strategies = over("has_analytic", an["id"])
                analytics.append({"id": an["ext_id"], "platforms": loads(an["platforms"], []),
                                  "detection_strategy": ", ".join(f"{ds['ext_id']} {ds['name']}" for ds in strategies)
                                  or None})
                for ds in strategies:
                    for t in under("detects", ds["id"]):
                        techniques[t["ext_id"]] = f"{t['ext_id']} {t['name']}"
            out["analytics"] = {"count": len(analytics), "items": analytics[:limit]}
            out["techniques"] = {"count": len(techniques), "items": [techniques[k] for k in sorted(techniques)][:limit],
                                 "via": "the detection strategies of the analytics that use this data component"}
        return out

    def _relation_summary(self, node_id: str, limit: int = 15) -> dict[str, Any]:
        groups: dict[str, list[str]] = defaultdict(list)
        for e in self._edges(src=node_id):
            groups[f"{e['rel']} ->"].append(e["dst"])
        for e in self._edges(dst=node_id):
            groups[f"<- {e['rel']}"].append(e["src"])
        out = {}
        for key, ids in sorted(groups.items()):
            names = []
            for i in ids[:limit]:
                r = self._node(i)
                names.append(f"{i} {r['name']}" if r else f"{i} (not in loaded data)")
            out[key] = {"count": len(ids), "items": names}
        return out

    def _tactics(self, node_id: str) -> list[dict]:
        out = []
        for e in self._edges(src=node_id, rel="in_tactic"):
            r = self._node(e["dst"])
            if r:
                out.append({"id": r["id"], "name": r["name"]})
        return out

    def _active(self, node_ids: Iterable[str], kinds: set[str] | None = None) -> list[sqlite3.Row]:
        rows = []
        for i in node_ids:
            r = self._node(i)
            if r and not r["revoked"] and not r["deprecated"] and (kinds is None or r["kind"] in kinds):
                rows.append(r)
        return sorted(rows, key=lambda r: r["ext_id"])

    def mitigations(self, node_id: str) -> list[dict[str, str]]:
        """Active mitigations MITRE links to a technique (ATT&CK and ATLAS "mitigates" relationships)."""
        return [{"id": r["ext_id"], "name": r["name"], "framework": r["framework"]}
                for r in self._active([e["src"] for e in self._edges(dst=node_id, rel="mitigates")])]

    def _analytic_log_sources(self, analytic_id: str) -> list[dict[str, Any]]:
        """The log sources MITRE lists on an analytic, each with the data component it references."""
        sources = []
        for e in self._edges(src=analytic_id, rel="uses_data_component"):
            dc = self._node(e["dst"])
            for ls in (loads(e["detail"], {}) or {}).get("log_sources", []):
                sources.append({"data_component": f"{dc['ext_id']} {dc['name']}" if dc else e["dst"], **ls})
        return sources

    def detection_strategies(self, node_id: str) -> list[dict[str, Any]]:
        """ATT&CK detection strategies for a technique, with their analytics and log sources.

        Each analytic also carries MITRE's description and its tunable fields (``mutable_elements``)
        when MITRE publishes them.
        """
        detections = []
        for ds in self._active([e["src"] for e in self._edges(dst=node_id, rel="detects")]):
            analytics = []
            for an in self._active([e["dst"] for e in self._edges(src=ds["id"], rel="has_analytic")]):
                entry = {"id": an["ext_id"], "platforms": loads(an["platforms"], []),
                         "log_sources": self._analytic_log_sources(an["id"])}
                if an["description"]:
                    entry["description"] = an["description"]
                tunables = loads(an["extra"], {}).get("mutable_elements")
                if tunables:
                    entry["mutable_elements"] = tunables
                analytics.append(entry)
            detections.append({"id": ds["ext_id"], "name": ds["name"], "analytics": analytics})
        return detections

    def technique_context(self, ref: str, limit: int = 15) -> dict[str, Any]:
        node_id, warnings, row = self._technique(ref)
        out = self.summarize(row, desc_chars=600)
        out["platforms"] = loads(row["platforms"], [])
        out["tactics"] = self._tactics(node_id)
        parent = self._edges(src=node_id, rel="subtechnique_of")
        if parent:
            out["parent"] = self.summarize(self._node(parent[0]["dst"]))
        subs = self._active([e["src"] for e in self._edges(dst=node_id, rel="subtechnique_of")])
        if subs:
            out["subtechniques"] = [f"{r['ext_id']} {r['name']}" for r in subs]

        users = self._active([e["src"] for e in self._edges(dst=node_id, rel="uses")])
        by_kind: dict[str, list[str]] = defaultdict(list)
        for r in users:
            by_kind[r["kind"]].append(f"{r['ext_id']} {r['name']}")
        out["used_by"] = {k: {"count": len(v), "items": v[:limit]} for k, v in by_kind.items()}

        out["mitigations"] = [f"{m['id']} {m['name']}" for m in self.mitigations(node_id)]

        detections = self.detection_strategies(node_id)
        out["detection_strategies"] = detections[:limit]
        if len(detections) > limit:
            out["detection_strategies_total"] = len(detections)

        targets = self._active([e["dst"] for e in self._edges(src=node_id, rel="targets")])
        if targets:
            out["targets_assets"] = [f"{r['ext_id']} {r['name']}" for r in targets]

        cm = self.countermeasures(node_id, limit=limit)
        out["d3fend"] = {
            k: cm[k] for k in ("status", "total", "official", "derived", "by_tactic", "notes") if k in cm
        }
        out["d3fend"]["countermeasures"] = [
            {k: m[k] for k in ("d3fend_id", "name", "tactic", "provenance", "via")} for m in cm["countermeasures"]
        ]
        out["crosswalk"] = self.crosswalk(node_id)["links"]
        if warnings:
            out["warnings"] = warnings
        return out

    def countermeasures(self, ref: str, tactic: str | None = None, limit: int = 25,
                        include_derived: bool = True) -> dict[str, Any]:
        node_id, warnings, row = self._technique(ref)
        status = self._mapping_status()
        results: dict[str, dict[str, Any]] = {}

        def collect(target: str, provenance: str, via: str | None) -> None:
            for e in self._edges(dst=target, rel="counters"):
                cm = self._node(e["src"])
                if cm is None or cm["deprecated"]:
                    continue
                detail = loads(e["detail"], {}) or {}
                extra = loads(cm["extra"], {})
                entry = results.get(cm["id"])
                if entry and (entry["provenance"] == "official" or provenance == "derived"):
                    continue
                results[cm["id"]] = {
                    "d3fend_id": cm["ext_id"],
                    "name": cm["name"],
                    "tactic": extra.get("tactic") or detail.get("tactic"),
                    "provenance": provenance,
                    "via": via,
                    "target": target,
                    "paths": detail.get("paths", [])[:6],
                    "url": cm["url"],
                    **({"target_revoked_in_loaded_attack": True} if detail.get("target_revoked") else {}),
                }

        def related_attack(attack_id: str, prefix: str = "") -> None:
            """Derived paths around one ATT&CK technique: parent, sub-techniques, revoked predecessors."""
            parent = self._edges(src=attack_id, rel="subtechnique_of")
            if parent:
                collect(parent[0]["dst"], "derived", f"{prefix}parent technique {parent[0]['dst']}")
            for e in self._edges(dst=attack_id, rel="subtechnique_of"):
                collect(e["src"], "derived", f"{prefix}sub-technique {e['src']}")
            # Revoked IDs that D3FEND still maps and that ATT&CK now points at this technique.
            for e in self._edges(dst=attack_id, rel="revoked_by"):
                collect(e["src"], "derived",
                        f"{prefix}revoked ID {e['src']} (ATT&CK replaced it with this technique; D3FEND still maps the old ID)")

        collect(node_id, "official", None)
        notes = []
        f3_native = False
        if include_derived:
            fw = row["framework"]
            if fw == "attack":
                related_attack(node_id)
            elif fw in ("f3", "atlas"):
                rel = "reuses_attack_id" if fw == "f3" else "references_attack"
                links = self._edges(src=node_id, rel=rel)
                for e in links:
                    target = self.resolve(e["dst"])["id"]
                    if fw == "f3":
                        lead = f"F3 reuses ATT&CK ID {e['dst']} (F3's definition differs; verify fit)"
                    else:
                        lead = f"ATLAS references ATT&CK {e['dst']}"
                    if target != e["dst"]:
                        lead += f", revoked in ATT&CK and replaced by {target}"
                    collect(target, "derived", lead)
                    related_attack(target, prefix=lead + " -> ")
                if fw == "f3" and not links:
                    f3_native = True
                    notes.append("F3-native technique: D3FEND publishes no mappings for F3, and F3 has not published mitigations yet.")
        items = sorted(
            results.values(),
            key=lambda r: (r["provenance"] != "official",
                           TACTIC_ORDER_D3FEND.index(r["tactic"]) if r["tactic"] in TACTIC_ORDER_D3FEND else 99,
                           r["name"]),
        )
        before = len(items)
        if tactic:
            if tactic.lower() not in {t.lower() for t in TACTIC_ORDER_D3FEND}:
                raise NotFound(f"unknown D3FEND tactic {tactic!r}; choose from {', '.join(TACTIC_ORDER_D3FEND)}")
            items = [i for i in items if (i["tactic"] or "").lower() == tactic.lower()]
            if before and not items:
                notes.append(f"{before} countermeasures exist for this technique, none in tactic {tactic}.")
        by_tactic: dict[str, int] = defaultdict(int)
        for i in items:
            by_tactic[i["tactic"] or "unknown"] += 1
        known = set(self.meta("d3fend_known_offensive_ids", []) or [])
        predates = bool(known) and row["framework"] in ("attack", "atlas") and row["ext_id"] not in known
        if status != "loaded":
            notes.append("D3FEND published mappings are not loaded in this database; countermeasure results are unavailable, not empty.")
        elif not items and not f3_native and not tactic:
            notes.append("No D3FEND mapping for this technique. That is a gap in D3FEND coverage, not evidence that no defense applies.")
            if predates:
                notes.append(
                    f"{row['ext_id']} is not in the loaded D3FEND ontology "
                    f"({self.source_versions().get('d3fend-ontology')}), which predates it. Expect mappings after D3FEND's next release."
                )
        # Why the list is empty, as one machine-readable value (None when it is not empty).
        if status != "loaded" or self._source_status("d3fend-ontology") != "loaded":
            gap_reason: str | None = "unavailable"
        elif items:
            gap_reason = None
        elif row["framework"] == "f3" and not self._edges(src=node_id, rel="reuses_attack_id"):
            gap_reason = "f3_native"
        elif tactic and before:
            gap_reason = "none_in_tactic"
        elif predates:
            gap_reason = "predates"
        else:
            gap_reason = "no_mapping"
        return {
            "technique": self.summarize(row),
            "status": status,
            "gap_reason": gap_reason,
            "total": len(items),
            "official": sum(1 for i in items if i["provenance"] == "official"),
            "derived": sum(1 for i in items if i["provenance"] == "derived"),
            "by_tactic": dict(by_tactic),
            "countermeasures": items[: max(1, min(limit, 200))],
            "notes": notes,
            **({"warnings": warnings} if warnings else {}),
        }

    def _mapping_status(self) -> str:
        return self._source_status("d3fend-mappings")

    def _source_status(self, key: str) -> str:
        row = self.conn.execute("SELECT status FROM sources WHERE key = ?", (key,)).fetchone()
        return row["status"] if row else "not-configured"

    def crosswalk(self, ref: str) -> dict[str, Any]:
        node_id, warnings = self._ref_resolved(ref)
        row = self._node(node_id)
        links = []
        cross = ("references_attack", "reuses_attack_id")
        for e in self._edges(src=node_id):
            if e["rel"] in cross:
                links.append(self._link(e, e["dst"], "out"))
        for e in self._edges(dst=node_id):
            if e["rel"] in cross:
                links.append(self._link(e, e["src"], "in"))
        cm_official = len(self._edges(dst=node_id, rel="counters"))
        out = {"node": self.summarize(row), "links": links, "d3fend_official_countermeasures": cm_official}
        if row["framework"] in ("f3", "atlas"):
            for link in links:
                n = len(self._edges(dst=link["id"], rel="counters"))
                if n:
                    link["d3fend_countermeasures_via_this_link"] = {"count": n, "provenance": "derived"}
        if warnings:
            out["warnings"] = warnings
        return out

    def _link(self, edge: sqlite3.Row, other: str, direction: str) -> dict[str, Any]:
        r = self._node(other)
        detail = loads(edge["detail"], {}) or {}
        link = {
            "rel": edge["rel"],
            "direction": direction,
            "id": other,
            "name": r["name"] if r else None,
            "provenance": edge["provenance"],
            "source": edge["source"],
        }
        for flag in ("target_missing", "target_revoked", "target_deprecated", "revoked_by", "note"):
            if flag in detail:
                link[flag] = detail[flag]
        return link

    def actor_techniques(self, ref: str, include_software: bool = False, limit: int = 300) -> dict[str, Any]:
        node_id, warnings = self._ref_resolved(ref)
        row = self._node(node_id)
        for kind in ("group", "software", "campaign"):
            if row["kind"] in ("group", "software", "campaign"):
                break
            try:
                node_id, warnings = self._ref_resolved(ref, kind=kind)
                row = self._node(node_id)
            except NotFound:
                continue
        if row["kind"] not in ("group", "software", "campaign"):
            raise NotFound(f"{node_id} is a {row['kind']}; expected a group, software or campaign")
        techniques: dict[str, dict[str, Any]] = {}
        for e in self._edges(src=node_id, rel="uses"):
            t = self._node(e["dst"])
            if t and t["kind"] == "technique":
                resolved = self.resolve(t["id"])["id"]
                tr = self._node(resolved)
                if tr and not tr["deprecated"]:
                    techniques[resolved] = {"id": tr["ext_id"], "name": tr["name"], "provenance": "official", "via": None}
        software = []
        if include_software and row["kind"] in ("group", "campaign"):
            for e in self._edges(src=node_id, rel="uses"):
                s = self._node(e["dst"])
                if s and s["kind"] == "software":
                    software.append(f"{s['ext_id']} {s['name']}")
                    for e2 in self._edges(src=s["id"], rel="uses"):
                        t = self._node(self.resolve(e2["dst"])["id"])
                        if t and t["kind"] == "technique" and not t["deprecated"] and t["id"] not in techniques:
                            techniques[t["id"]] = {"id": t["ext_id"], "name": t["name"], "provenance": "derived", "via": f"software {s['ext_id']}"}
        items = sorted(techniques.values(), key=lambda t: t["id"])
        out = {
            "actor": self.summarize(row),
            "total": len(items),
            "techniques": items[:limit],
        }
        if software:
            out["software"] = software
        if warnings:
            out["warnings"] = warnings
        return out

    def compare_actors(self, refs: list[str], include_software: bool = False) -> dict[str, Any]:
        if len(refs) < 2:
            raise NotFound("compare_actors needs at least two actors")
        sets, labels = {}, {}
        notes = []
        if len(refs) > 8:
            notes.append(f"compared the first 8 of {len(refs)} actors")
        for ref in refs[:8]:
            data = self.actor_techniques(ref, include_software=include_software)
            key = data["actor"]["ext_id"]
            labels[key] = data["actor"]["name"]
            sets[key] = {t["id"] for t in data["techniques"]}
        keys = list(sets)
        shared = set.intersection(*sets.values())
        pairwise = []
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                union = sets[a] | sets[b]
                pairwise.append({"a": a, "b": b, "shared": len(sets[a] & sets[b]),
                                 "jaccard": round(len(sets[a] & sets[b]) / len(union), 3) if union else 0.0})
        return {
            "actors": {k: {"name": labels[k], "techniques": len(sets[k])} for k in keys},
            "shared_by_all": sorted(shared),
            "unique": {k: sorted(sets[k] - set().union(*(sets[o] for o in keys if o != k))) for k in keys},
            "pairwise": pairwise,
            **({"notes": notes} if notes else {}),
        }

    def coverage_gaps(self, refs: list[str]) -> dict[str, Any]:
        rows = []
        summary = defaultdict(list)
        for ref in refs[:MAX_LIST_ITEMS]:
            try:
                node_id, warnings, n = self._technique(str(ref))
            except NotFound as exc:
                rows.append({"input": str(ref)[:MAX_REF_CHARS], "error": str(exc)})
                summary["not_found_or_not_technique"].append(str(ref)[:MAX_REF_CHARS])
                continue
            entry = {
                "input": ref,
                "id": n["ext_id"],
                "framework": n["framework"],
                "name": n["name"],
                "mitigations": len(self._active([e["src"] for e in self._edges(dst=node_id, rel="mitigates")])),
                "detection_strategies": len(self._active([e["src"] for e in self._edges(dst=node_id, rel="detects")])),
            }
            cm = self.countermeasures(node_id, limit=200)
            entry["d3fend_official"] = sum(1 for c in cm["countermeasures"] if c["provenance"] == "official")
            entry["d3fend_derived"] = sum(1 for c in cm["countermeasures"] if c["provenance"] == "derived")
            if warnings:
                entry["warnings"] = warnings
            rows.append(entry)
            if entry["mitigations"] == 0:
                summary["no_mitigation"].append(entry["id"])
            if entry["detection_strategies"] == 0 and n["framework"] == "attack":
                summary["no_detection_strategy"].append(entry["id"])
            if entry["d3fend_official"] == 0:
                summary["no_official_d3fend"].append(entry["id"])
        if len(refs) > MAX_LIST_ITEMS:
            summary["truncated"] = [f"checked the first {MAX_LIST_ITEMS} of {len(refs)} techniques"]
        return {
            "d3fend_mappings": self._mapping_status(),
            "summary": {k: v for k, v in summary.items()},
            "techniques": rows,
        }

    # -- detection model -----------------------------------------------------
    def _strategies_and_analytics(self, node_id: str) -> tuple[list[sqlite3.Row], list[tuple[sqlite3.Row, str]]]:
        """A technique's active detection strategies, and their active analytics with the strategy's ID."""
        strategies = self._active([e["src"] for e in self._edges(dst=node_id, rel="detects")])
        analytics = [(an, ds["ext_id"]) for ds in strategies
                     for an in self._active([e["dst"] for e in self._edges(src=ds["id"], rel="has_analytic")])]
        return strategies, analytics

    def _analytic_refs(self, analytic_id: str) -> list[tuple[str, str | None, str]]:
        """An analytic's log-source references as (log source name, channel, data component node id)."""
        refs: list[tuple[str, str | None, str]] = []
        for e in self._edges(src=analytic_id, rel="uses_data_component"):
            for ls in (loads(e["detail"], {}) or {}).get("log_sources", []):
                ref = (" ".join((ls.get("name") or "").split()), ls.get("channel"), e["dst"])
                if ref[0] and ref not in refs:
                    refs.append(ref)
        return refs

    @staticmethod
    def _on_platform(row: sqlite3.Row, platform: str | None) -> bool:
        return not platform or platform.lower() in {p.lower() for p in loads(row["platforms"], [])}

    def _canonical_platform(self, platform: str) -> str:
        known: dict[str, str] = {}
        for r in self.conn.execute(
                "SELECT platforms FROM nodes WHERE framework = 'attack' AND kind IN ('technique', 'analytic')"):
            for p in loads(r["platforms"], []):
                known.setdefault(p.lower(), p)
        found = known.get(" ".join(str(platform).split()).lower())
        if found is None:
            raise NotFound(f"unknown platform {platform!r}; choose from {', '.join(sorted(set(known.values())))}")
        return found

    def _log_source_index(self) -> tuple[dict[str, str], dict[str, dict[str | None, str | None]]]:
        """Every log source name MITRE uses on an analytic, keyed by its lowercase form, and for each name the
        channels its analytics use (normalized channel -> MITRE's spelling; None for no particular channel)."""
        names: dict[str, str] = {}
        channels: dict[str, dict[str | None, str | None]] = defaultdict(dict)
        for r in self.conn.execute("SELECT detail FROM edges WHERE rel = 'uses_data_component'"):
            for ls in (loads(r["detail"], {}) or {}).get("log_sources", []):
                name = " ".join((ls.get("name") or "").split())
                if name:
                    names.setdefault(name.lower(), name)
                    channels[name.lower()].setdefault(_norm_channel(ls.get("channel")), ls.get("channel"))
        return names, channels

    def _data_component_names(self) -> dict[str, str]:
        """Active ATT&CK data components by normalized name, as "DC0032 Process Creation"."""
        return {_norm(r["name"]): f"{r['ext_id']} {r['name']}" for r in self.conn.execute(
            "SELECT ext_id, name FROM nodes WHERE framework = 'attack' AND kind = 'data-component'"
            " AND revoked = 0 AND deprecated = 0 ORDER BY ext_id DESC")}

    def telemetry_coverage(self, log_sources: list[str] | None = None, data_components: list[str] | None = None,
                           platform: str | None = None, techniques: list[str] | None = None,
                           actor: str | None = None, include_software: bool = False, limit: int = 50,
                           layer: bool = False, domain: str | None = None,
                           max_layer_techniques: int | None = None) -> dict[str, Any]:
        """Which techniques the telemetry you collect can detect, by MITRE's analytics, and where you are blind.

        ``log_sources`` are names as MITRE writes them on analytics ("WinEventLog:Sysmon"), optionally followed
        by a channel ("WinEventLog:Sysmon EventCode=10"); a name alone matches every channel of that log source.
        ``data_components`` are IDs or names. The target is ``techniques``, an ``actor``'s techniques (as in
        ``actor_techniques``), or every active ATT&CK technique (on ``platform``, if given), in ``domain`` (all
        three ATT&CK domains by default). With ``max_layer_techniques``, a layer that would place more techniques
        is left out with a note (the MCP server sets it; the CLI does not).
        """
        if techniques and actor:
            raise NotFound("give techniques or an actor, not both")
        if domain is not None and domain not in ATTACK_DOMAINS:
            raise NotFound(f"unknown domain {domain!r}; choose from {', '.join(ATTACK_DOMAINS)}")
        domains = [domain] if domain else list(ATTACK_DOMAINS)
        limit = max(1, min(int(limit), MAX_LIST_ITEMS))
        warnings: list[str] = []
        notes: list[str] = []
        log_sources = _capped(_distinct(log_sources), MAX_LIST_ITEMS, notes,
                              "log_sources: used the first {cap} of {n} distinct entries")
        data_components = _capped(_distinct(data_components), MAX_LIST_ITEMS, notes,
                                  "data_components: used the first {cap} of {n} distinct entries")
        if not log_sources and not data_components:
            raise NotFound("give log_sources or data_components: the telemetry you collect")
        platform = self._canonical_platform(platform) if platform else None

        # The telemetry: log source names with the channels collected (None = every channel), and data components.
        known, used_channels = self._log_source_index()
        component_names = self._data_component_names()
        wanted: dict[str, set[str] | None] = {}
        codes: dict[str, set[int]] = defaultdict(set)
        shown: list[str] = []
        unknown: list[str] = []
        for raw in log_sources:
            name, channel = _split_log_source(raw, known)
            key = name.lower()
            component = component_names.get(_norm(raw))
            if component:
                warnings.append(
                    f"{raw!r} is the name of data component {component}"
                    + (", and also a log source name; if you meant the data component, pass it in data_components"
                       if _norm(raw) in known else ", not a log source name; pass it in data_components instead"))
            elif key not in known:
                unknown.append((raw, key))
            elif channel is not None:
                used = used_channels[key]
                normalized, need = _norm_channel(channel), _event_codes(_norm_channel(channel))
                if not (None in used or normalized in used
                        or (need and any(need & (_event_codes(c) or set()) for c in used if c))):
                    # Shortest first, so plain channels such as EventCode=10 lead over prose descriptions.
                    spelled = [v if len(v) <= 60 else v[:59] + "…"
                               for v in sorted((v for v in used.values() if v), key=lambda v: (len(v), v))]
                    warnings.append(
                        f"{raw!r}: no ATT&CK analytic uses {name} with channel {channel!r}; its analytics use "
                        + ", ".join(spelled[:8]) + (f" and {len(spelled) - 8} more" if len(spelled) > 8 else ""))
            shown.append(f"{name} {channel}" if channel else name)
            channel = _norm_channel(channel)
            if channel is None:
                wanted[key] = None
            elif wanted.get(key, set()) is not None:
                wanted.setdefault(key, set()).add(channel)
                codes[key] |= _event_codes(channel) or set()
        for raw, key in unknown[:_WARNINGS_PER_KIND]:
            close = [known[k] for k in difflib.get_close_matches(key, list(known), n=3, cutoff=0.6)]
            warnings.append(f"{raw!r} names no log source used by the loaded ATT&CK analytics"
                            + (f"; did you mean {', '.join(close)}?" if close else ""))
        if len(unknown) > _WARNINGS_PER_KIND:
            warnings.append(f"... and {len(unknown) - _WARNINGS_PER_KIND} more log source names match nothing in the "
                            "loaded ATT&CK analytics")
        dcs: dict[str, str] = {}
        unresolved: list[str] = []
        for ref in data_components:
            try:
                node_id, found_notes = self._ref_resolved(ref, kind="data-component")
            except NotFound as exc:
                unresolved.append(f"data component {ref!r} ignored: {exc}")
                continue
            row = self._node(node_id)
            if row["kind"] != "data-component":
                warnings.append(f"{ref!r} is {row['id']}, a {row['kind']}, not a data component; ignored")
                continue
            warnings.extend(found_notes)
            dcs[node_id] = f"{row['ext_id']} {row['name']}"
        warnings.extend(unresolved[:_WARNINGS_PER_KIND])
        if len(unresolved) > _WARNINGS_PER_KIND:
            warnings.append(f"... and {len(unresolved) - _WARNINGS_PER_KIND} more data components match nothing")

        # The target techniques, in the chosen domains.
        targets: list[tuple[str, str | None]] = []
        not_found: list[str] = []
        if actor:
            data = self.actor_techniques(actor, include_software=include_software, limit=10**6)
            warnings.extend(data.get("warnings", []))
            target: dict[str, Any] = {"kind": "actor", "actor": data["actor"]}
            targets = [(f"attack:{t['id']}", t["via"]) for t in data["techniques"]]
        elif techniques:
            refs = _capped(_distinct(techniques), MAX_LIST_ITEMS, notes, "checked the first {cap} of {n} techniques")
            for ref in refs:
                try:
                    node_id, found_notes, _ = self._technique(ref)
                except NotFound:
                    not_found.append(ref)
                    continue
                warnings.extend(found_notes)
                if node_id not in {n for n, _ in targets}:
                    targets.append((node_id, None))
            target = {"kind": "techniques"}
        else:
            rows = self.conn.execute("SELECT id, platforms, domains FROM nodes WHERE framework = 'attack'"
                                     " AND kind = 'technique' AND revoked = 0 AND deprecated = 0")
            targets = [(r["id"], None) for r in rows
                       if self._on_platform(r, platform) and set(loads(r["domains"], [])) & set(domains)]
            target = {"kind": "all"}
            notes.append("target: every active ATT&CK technique" + (f" MITRE lists for {platform}" if platform else "")
                         + f" in {', '.join(domains)}")
        outside: list[str] = []
        in_domain: list[tuple[str, str | None]] = []
        for node_id, via in targets:
            row = self._node(node_id)
            if row is not None and set(loads(row["domains"], [])) & set(domains):
                in_domain.append((node_id, via))
            elif row is not None:
                outside.append(row["ext_id"])
        targets = in_domain
        target.update({"domains": domains, "techniques": len(targets)})

        legend: dict[str, str] = {}

        def label(ref: tuple[str, str | None, str]) -> str:
            name, channel, dc_id = ref
            dc = self._node(dc_id)
            ext_id = dc["ext_id"] if dc else dc_id
            if dc:
                legend[ext_id] = dc["name"]
            text = name if _norm_channel(channel) is None else f"{name} {' '.join(channel.split())}"
            return f"{text} ({ext_id})"

        def status(ref: tuple[str, str | None, str]) -> str:
            """match: the reference is in the telemetry; touch: some of its event codes are; none: not at all."""
            name, channel, dc_id = ref
            if dc_id in dcs:
                return "match"
            key = name.lower()
            if key not in wanted:
                return "none"
            have, channel = wanted[key], _norm_channel(channel)
            if have is None or channel is None or channel in have:
                return "match"
            need = _event_codes(channel)
            if need and need <= codes[key]:
                return "match"
            if need and need & codes[key]:
                return "touch"
            return "none"

        results: dict[str, list[dict[str, Any]]] = {cls: [] for cls in TELEMETRY_CLASSES}
        scores: dict[str, int] = {}
        comments: dict[str, str] = {}
        for node_id, via in targets:
            row = self._node(node_id)
            if row is None:
                continue
            entry: dict[str, Any] = {"id": row["ext_id"], "name": row["name"]}
            if via:
                entry["via"] = via
            strategies, analytics = self._strategies_and_analytics(node_id)
            on_platform = [(an, det) for an, det in analytics if self._on_platform(an, platform)]
            if not strategies:
                cls, comment = "no_detection_strategy", "no ATT&CK detection strategy"
            elif platform and not on_platform:
                cls, comment = "no_analytic_for_platform", f"no ATT&CK analytic for {platform}"
                entry["analytic_platforms"] = sorted({p for an, _ in analytics for p in loads(an["platforms"], [])})
            else:
                evaluated = []
                for an, det in on_platform:
                    refs = self._analytic_refs(an["id"])
                    states = [status(r) for r in refs]
                    evaluated.append({
                        "id": an["ext_id"], "detection_strategy": det, "platforms": loads(an["platforms"], []),
                        "full": bool(refs) and all(s == "match" for s in states),
                        "uses": any(s != "none" for s in states),
                        "matched": [label(r) for r, s in zip(refs, states) if s == "match"],
                        "missing": [label(r) for r, s in zip(refs, states) if s != "match"],
                    })
                full = [x for x in evaluated if x["full"]]
                touching = sorted((x for x in evaluated if x["uses"] and not x["full"]),
                                  key=lambda x: (len(x["missing"]), x["id"]))
                base = ("id", "detection_strategy", "platforms")
                if full:
                    cls = "covered"
                    entry["analytics"] = [{**{k: x[k] for k in base}, "log_sources": x["matched"]}
                                          for x in full[:_ANALYTICS_PER_TECHNIQUE]]
                    comment = "covered: " + ", ".join(f"{x['id']} ({x['detection_strategy']})" for x in full[:3])
                    shown_analytics = full
                elif touching:
                    cls = "partial"
                    entry["analytics"] = [{**{k: x[k] for k in base}, "matched": x["matched"], "missing": x["missing"]}
                                          for x in touching[:_ANALYTICS_PER_TECHNIQUE]]
                    comment = f"partial: {touching[0]['id']} also needs " + "; ".join(touching[0]["missing"][:3])
                    shown_analytics = touching
                else:
                    cls = "blind"
                    missing = list(dict.fromkeys(m for x in evaluated for m in x["missing"]))
                    entry["analytics_checked"] = len(evaluated)
                    entry["missing"] = missing[:10]
                    if len(missing) > 10:
                        entry["missing_total"] = len(missing)
                    comment = f"blind: none of its {len(evaluated)} analytics uses this telemetry"
                    shown_analytics = []
                if len(shown_analytics) > _ANALYTICS_PER_TECHNIQUE:
                    entry["analytics_total"] = len(shown_analytics)
            results[cls].append(entry)
            if cls in TELEMETRY_SCORES:
                scores[row["ext_id"]] = TELEMETRY_SCORES[cls]
            comments[row["ext_id"]] = comment

        for cls, items in results.items():
            items.sort(key=lambda e: e["id"])
            if len(items) > limit:
                notes.append(f"{cls}: showing the first {limit} of {len(items)} techniques")
        out: dict[str, Any] = {
            "basis": TELEMETRY_BASIS,
            "telemetry": {"log_sources": shown, "data_components": sorted(dcs.values()), "platform": platform},
            "target": target,
            "counts": {cls: len(items) for cls, items in results.items()},
            "techniques": {cls: items[:limit] for cls, items in results.items()},
            "data_components": dict(sorted(legend.items())),
        }
        if outside:
            out["outside_domain"] = sorted(outside)[:MAX_LIST_ITEMS]
        if layer and max_layer_techniques is not None and len(targets) > max_layer_techniques:
            notes.append(f"layer omitted: it would place {len(targets)} techniques, more than the "
                         f"{max_layer_techniques} an MCP response carries; run `countermap coverage ... --layer FILE` "
                         "for the full layer")
        elif layer:
            from .emit.navigator import coverage_layers  # imported here: the emit package imports this module

            title = "Telemetry coverage"
            if actor:
                title += f": {target['actor']['name']} ({target['actor']['ext_id']})"
            telemetry = ", ".join(shown + sorted(dcs.values()))
            out["navigator"] = coverage_layers(
                self, [n for n, _ in targets], name=title[:200],
                description=f"Telemetry: {telemetry}"[:600] + f" ({platform or 'all platforms'}). Coverage "
                            + TELEMETRY_BASIS,
                scores=scores, comments=comments, labels={2: "covered", 1: "partial", 0: "blind"})
            warnings.extend(out["navigator"].pop("warnings"))
        if not_found:
            out["not_found"] = not_found
        if notes:
            out["notes"] = notes
        if warnings:
            out["warnings"] = list(dict.fromkeys(warnings))
        return out

    # -- rule coverage -------------------------------------------------------
    def _users_index(self) -> tuple[dict[str, dict[str, dict[str, set[str]]]], dict[str, sqlite3.Row]]:
        """Active groups and campaigns that use each technique, directly or through software they use.

        Revoked technique targets are followed to their replacement, as ``actor_techniques`` does.
        """
        nodes = {r["id"]: r for r in self.conn.execute(
            "SELECT id, ext_id, name, kind, revoked, deprecated FROM nodes WHERE framework = 'attack'")}
        revoked_by: dict[str, str] = {}
        for e in self.conn.execute("SELECT src, dst FROM edges WHERE rel = 'revoked_by'"):
            revoked_by.setdefault(e["src"], e["dst"])

        def current(node_id: str) -> str:
            for _ in range(10):
                row = nodes.get(node_id)
                if row is None or not row["revoked"] or node_id not in revoked_by:
                    break
                node_id = revoked_by[node_id]
            return node_id

        techniques_of: dict[str, set[str]] = defaultdict(set)
        software_of: dict[str, set[str]] = defaultdict(set)
        for e in self.conn.execute("SELECT src, dst FROM edges WHERE rel = 'uses'"):
            dst = nodes.get(e["dst"])
            if dst is None or e["src"] not in nodes:
                continue
            if dst["kind"] == "technique":
                techniques_of[e["src"]].add(current(e["dst"]))
            elif dst["kind"] == "software":
                software_of[e["src"]].add(e["dst"])
        # users[technique][kind][actor] = the software it reaches the technique through; empty when ATT&CK links
        # the actor to the technique directly (an official link), non-empty when only through software (derived).
        users: dict[str, dict[str, dict[str, set[str]]]] = defaultdict(lambda: {"group": {}, "campaign": {}})
        for actor, row in nodes.items():
            if row["kind"] not in ("group", "campaign") or row["revoked"] or row["deprecated"]:
                continue
            direct = techniques_of.get(actor, set())
            for technique in direct:
                users[technique][row["kind"]][actor] = set()
            for software in software_of.get(actor, ()):
                for technique in techniques_of.get(software, set()) - direct:
                    users[technique][row["kind"]].setdefault(actor, set()).add(software)
        return users, nodes

    def rule_coverage(self, techniques: list[str], *, scope_actors: list[str] | None = None,
                      platform: str | None = None, tactics: list[str] | None = None,
                      domain: str = "enterprise-attack", limit: int = 50, layer: bool = False,
                      max_layer_techniques: int | None = None) -> dict[str, Any]:
        """What a ruleset's ATT&CK technique IDs cover in scope, and the gaps ranked by how many groups use them.

        The scope is the domain's active techniques, filtered by ``platform`` and ``tactics``; with
        ``scope_actors`` (groups, software or campaigns) it is only their techniques. A technique is covered when
        its own ID is listed; partial when its parent is listed, or when it is a parent with some or all of its
        sub-techniques listed but not itself; uncovered otherwise. With ``max_layer_techniques``, a layer that
        would place more techniques is left out with a note (the MCP server sets it; the CLI does not).
        """
        if domain not in ATTACK_DOMAINS:
            raise NotFound(f"unknown domain {domain!r}; choose from {', '.join(ATTACK_DOMAINS)}")
        limit = max(1, min(int(limit), MAX_LIST_ITEMS))
        warnings: list[str] = []
        notes: list[str] = []
        platform = self._canonical_platform(platform) if platform else None

        # The ruleset: ATT&CK technique IDs, each taken once, revoked ones followed to their replacement.
        entries = [t for t in (techniques or []) if str(t).strip()]
        refs = _distinct(entries)
        if len(refs) < len(entries):
            notes.append(f"{len(entries)} entries hold {len(refs)} distinct technique IDs; each is counted once")
        refs = _capped(refs, MAX_RULE_TECHNIQUES, notes, "read the first {cap} of {n} technique IDs")
        scope_actors = _capped(_distinct(scope_actors), MAX_SCOPE_ACTORS, notes,
                               "scope_actors: used the first {cap} of {n} actors")
        tactics = _capped(_distinct(tactics), MAX_TACTICS, notes, "tactics: used the first {cap} of {n} tactics")
        listed: set[str] = set()
        not_found: list[str] = []
        for ref in refs:
            try:
                node_id, found = self._ref_resolved(ref, framework="attack")
            except NotFound:
                not_found.append(ref)
                continue
            row = self._node(node_id)
            if row["kind"] != "technique":
                not_found.append(ref)
                warnings.append(f"{ref} is {row['id']}, a {row['kind']}, not a technique")
                continue
            warnings.extend(found)
            listed.add(node_id)

        # Tactics of the domain, in matrix order, and the ones asked for.
        tactic_rows = [r for r in self.conn.execute(
            "SELECT * FROM nodes WHERE framework = 'attack' AND kind = 'tactic' AND revoked = 0 AND deprecated = 0")
            if domain in loads(r["domains"], [])]
        tactic_name = {r["id"]: r["name"] for r in tactic_rows}
        tactic_rank = {r["id"]: (loads(r["extra"], {}).get("order", 99), r["name"]) for r in tactic_rows}
        selected: set[str] | None = None
        if tactics:
            selected = set()
            for wanted in tactics:
                key = _norm(str(wanted)).replace("-", " ")
                match = [r["id"] for r in tactic_rows
                         if key in {_norm(r["name"]).replace("-", " "), r["ext_id"].lower(),
                                    _norm(loads(r["extra"], {}).get("shortname")).replace("-", " ")}]
                if not match:
                    raise NotFound(f"unknown tactic {wanted!r} in {domain}; choose from "
                                   f"{', '.join(sorted(set(tactic_name.values())))}")
                selected.update(match)
        tactics_of: dict[str, list[str]] = defaultdict(list)
        for e in self.conn.execute("SELECT src, dst FROM edges WHERE rel = 'in_tactic'"):
            if e["dst"] in tactic_name:
                tactics_of[e["src"]].append(e["dst"])
        for ids in tactics_of.values():
            ids.sort(key=tactic_rank.get)

        # The scope.
        active = {r["id"]: r for r in self.conn.execute(
            "SELECT id, ext_id, name, domains, platforms FROM nodes WHERE framework = 'attack' AND kind = 'technique'"
            " AND revoked = 0 AND deprecated = 0")}
        scope = {i: r for i, r in active.items()
                 if domain in loads(r["domains"], []) and self._on_platform(r, platform)
                 and (selected is None or selected & set(tactics_of.get(i, [])))}
        scope_users: dict[str, set[str]] | None = None
        actor_labels: list[str] | None = None
        if scope_actors:
            scope_users, actor_labels = defaultdict(set), []
            for ref in scope_actors:
                data = self.actor_techniques(ref, include_software=True, limit=10**6)
                label = f"{data['actor']['ext_id']} {data['actor']['name']}"
                actor_labels.append(label)
                warnings.extend(data.get("warnings", []))
                for t in data["techniques"]:
                    mark = f"derived: via {t['via']}" if t["via"] else "direct"
                    scope_users[f"attack:{t['id']}"].add(f"{label} ({mark})")
            scope = {i: r for i, r in scope.items() if i in scope_users}

        parent_of: dict[str, str] = {}
        subs_of: dict[str, list[str]] = defaultdict(list)
        for e in self.conn.execute("SELECT src, dst FROM edges WHERE rel = 'subtechnique_of'"):
            if e["src"] in active:
                parent_of[e["src"]] = e["dst"]
                subs_of[e["dst"]].append(e["src"])

        users, nodes = self._users_index()
        records = []
        for node_id, row in scope.items():
            reason = None
            subs = sorted(subs_of.get(node_id, []), key=lambda s: active[s]["ext_id"])
            hit = [active[s]["ext_id"] for s in subs if s in listed]
            if node_id in listed:
                status = "covered"
            elif parent_of.get(node_id) in listed:
                status, reason = "partial", f"covered via parent {nodes[parent_of[node_id]]['ext_id']}"
            elif hit:
                shown = ", ".join(hit[:5]) + (", ..." if len(hit) > 5 else "")
                status = "partial"
                reason = (f"all {len(subs)} sub-techniques covered ({shown}), but not {row['ext_id']} itself"
                          if len(hit) == len(subs) else f"{len(hit)} of {len(subs)} sub-techniques covered ({shown})")
            else:
                status = "uncovered"
            records.append({
                "node_id": node_id, "id": row["ext_id"], "name": row["name"], "status": status, "reason": reason,
                "tactic_ids": [t for t in tactics_of.get(node_id, []) if selected is None or t in selected],
                "groups": users[node_id]["group"],  # group -> the software it goes through; empty when direct
                "campaigns": len(users[node_id]["campaign"]),
                "scope": scope_users.get(node_id, set()) if scope_users is not None else None,
            })

        def rank(rec: dict[str, Any]) -> tuple:
            # With scope_actors: how many of them use it, then the overall group count; then campaigns, then ID.
            scoped = -len(rec["scope"]) if scope_users is not None else 0
            return scoped, -len(rec["groups"]), -rec["campaigns"], rec["id"]

        def entry(rec: dict[str, Any]) -> dict[str, Any]:
            strategies, analytics = self._strategies_and_analytics(rec["node_id"])
            components: dict[str, str] = {}
            for an, _ in analytics:
                if self._on_platform(an, platform):
                    for _, _, dc_id in self._analytic_refs(an["id"]):
                        if dc_id in nodes:
                            components[nodes[dc_id]["ext_id"]] = f"{nodes[dc_id]['ext_id']} {nodes[dc_id]['name']}"
            out = {"id": rec["id"], "name": rec["name"], "tactics": [tactic_name[t] for t in rec["tactic_ids"]],
                   "status": rec["status"]}
            if rec["reason"]:
                out["reason"] = rec["reason"]
            groups = rec["groups"]
            examples = []
            for g in sorted(groups, key=lambda g: (bool(groups[g]), nodes[g]["ext_id"]))[:5]:
                via = ", ".join(sorted(nodes[s]["ext_id"] for s in groups[g]))
                examples.append(f"{nodes[g]['ext_id']} {nodes[g]['name']} "
                                + (f"(derived: via software {via})" if via else "(direct)"))
            out["groups"] = {"count": len(groups), "direct": sum(1 for g in groups if not groups[g]),
                             "examples": examples}
            out["campaigns"] = rec["campaigns"]
            if rec["scope"] is not None:
                out["scope_actors"] = {"count": len(rec["scope"]), "items": sorted(rec["scope"])}
            out["detection_strategies"] = [ds["ext_id"] for ds in strategies]
            out["data_components"] = [components[k] for k in sorted(components)]
            return out

        by_status = {s: [r for r in records if r["status"] == s] for s in RULE_SCORES}
        gaps = sorted(by_status["uncovered"], key=rank) + sorted(by_status["partial"], key=rank)
        covered = sorted(by_status["covered"], key=lambda r: r["id"])
        for name, items in (("gaps", gaps), ("covered", covered)):
            if len(items) > limit:
                notes.append(f"{name}: showing the first {limit} of {len(items)}")
        by_tactic: dict[str, dict[str, int]] = {}
        for tid in sorted({t for r in records for t in r["tactic_ids"]}, key=tactic_rank.get):
            by_tactic[tactic_name[tid]] = {s: sum(1 for r in by_status[s] if tid in r["tactic_ids"]) for s in RULE_SCORES}
        out: dict[str, Any] = {
            "basis": RULE_BASIS,
            "counting": RULE_COUNTING,
            "scope": {"domain": domain, "platform": platform,
                      "tactics": sorted((tactic_name[t] for t in selected), key=lambda n: n) if selected else None,
                      "actors": actor_labels, "techniques": len(scope)},
            "rules": {"listed": len(refs), "resolved": len(listed), "in_scope": len(listed & scope.keys())},
            "totals": {"in_scope": len(scope), **{s: len(by_status[s]) for s in RULE_SCORES}},
            "by_tactic": by_tactic,
            "gaps": [entry(r) for r in gaps[:limit]],
            "covered": [entry(r) for r in covered[:limit]],
        }
        outside = sorted(nodes[i]["ext_id"] for i in listed - scope.keys())
        if outside:
            out["outside_scope"] = outside
        if layer and max_layer_techniques is not None and len(scope) > max_layer_techniques:
            notes.append(f"layer omitted: it would place {len(scope)} techniques, more than the {max_layer_techniques} "
                         "an MCP response carries; run `countermap rules-coverage ... --layer FILE` for the full layer")
        elif layer:
            from .emit.navigator import coverage_layers  # imported here: the emit package imports this module

            def comment(rec: dict[str, Any]) -> str:
                n = len(rec["groups"])
                direct = sum(1 for g in rec["groups"] if not rec["groups"][g])
                text = (f"{rec['status']}: {n} group{' uses' if n == 1 else 's use'} it ({direct} directly, "
                        f"{n - direct} only through their software, derived by Countermap)")
                if rec["scope"] is not None:
                    text += f"; {len(rec['scope'])} of the scope actors"
                return text + (f"; {rec['reason']}" if rec["reason"] else "")

            title = "Rule coverage" + (f": {', '.join(actor_labels)}" if actor_labels else "")
            out["navigator"] = coverage_layers(
                self, list(scope), name=title[:200], description="Rule coverage: " + RULE_BASIS + ". " + RULE_COUNTING,
                scores={r["id"]: RULE_SCORES[r["status"]] for r in records}, comments={r["id"]: comment(r) for r in records},
                labels={2: "covered", 1: "partial", 0: "uncovered"})
            warnings.extend(out["navigator"].pop("warnings"))
        if not_found:
            out["not_found"] = not_found
        if notes:
            out["notes"] = notes
        if warnings:
            out["warnings"] = list(dict.fromkeys(warnings))
        return out
