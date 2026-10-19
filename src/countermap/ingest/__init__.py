"""Build orchestration: resolve, fetch, verify, ingest, cross-check, atomically swap."""

from __future__ import annotations

import datetime as _dt
from collections import Counter
from pathlib import Path

from .. import __version__
from ..db import GraphWriter
from ..sources import FetchError, ResolvedSource, fetch, sha256_file
from .atlas import ingest_atlas
from .attack import ingest_attack, resolve_cross_bundle_references
from .d3fend import ingest_d3fend_mappings, ingest_d3fend_ontology
from .f3 import ingest_f3

ORDER = ["attack-enterprise", "attack-mobile", "attack-ics", "f3", "atlas", "d3fend-ontology", "d3fend-mappings"]
CROSS_RELATIONS = ("counters", "references_attack", "reuses_attack_id")


class BuildError(RuntimeError):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def prev_path(db_path: Path) -> Path:
    return db_path.with_name(db_path.stem + ".prev" + db_path.suffix)


def build(
    db_path: Path,
    sources: list[ResolvedSource],
    cache_dir: Path,
    *,
    verify_hashes: bool = False,
    keep_previous: bool = True,
    log=print,
) -> dict:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = db_path.with_name(db_path.name + ".building")
    writer = GraphWriter(tmp_path)
    report: dict = {"started_at": _now(), "countermap_version": __version__, "sources": []}
    by_key = {s.key: s for s in sources}

    for key in ORDER:
        src = by_key.get(key)
        if src is None:
            continue
        path = None
        errors = [] if src.url else ["no URL could be resolved (unknown upstream release version)"]
        used_url = None
        for candidate in [c for c in (src.url, *src.fallbacks) if c]:
            try:
                path = fetch(candidate, cache_dir)
                used_url = candidate
                break
            except FetchError as exc:
                errors.append(str(exc))
        if path is None:
            note = "; ".join(errors)
            writer.add_source(
                key, framework=src.framework, title=src.title, version=src.version, url=src.url,
                license=src.license, retrieved_at=_now(), status="unavailable", note=note,
            )
            writer.warnings.append(f"{key} unavailable: {note}")
            log(f"  ! {key}: unavailable ({'optional' if src.optional else 'required'})")
            if not src.optional and key != "d3fend-ontology":
                raise BuildError(f"required source {key} could not be fetched: {note}")
            continue

        digest = sha256_file(path)
        if verify_hashes and src.sha256 and src.sha256 != digest:
            raise BuildError(
                f"{key}: SHA-256 mismatch against lock (expected {src.sha256[:12]}, got {digest[:12]}). "
                "Upstream changed. Review it, then run `countermap lock` to accept."
            )

        log(f"  - ingesting {key} from {used_url}")
        if key == "d3fend-mappings" and not hasattr(writer, "d3fend_iri_to_id"):
            writer.warnings.append("d3fend-mappings skipped: the D3FEND ontology was not loaded")
            continue
        ingest = {
            "f3": ingest_f3, "atlas": ingest_atlas,
            "d3fend-ontology": ingest_d3fend_ontology, "d3fend-mappings": ingest_d3fend_mappings,
        }.get(key, ingest_attack)
        try:
            result = ingest(writer, path, key)
        except (ValueError, KeyError, TypeError) as exc:
            if not src.optional:
                raise BuildError(f"{key}: could not ingest {used_url}: {exc}") from exc
            writer.add_source(
                key, framework=src.framework, title=src.title, version=src.version, url=used_url,
                sha256=digest, license=src.license, retrieved_at=_now(), status="failed", note=str(exc),
            )
            writer.warnings.append(f"{key} failed to ingest and was skipped: {exc}")
            log(f"  ! {key}: failed to ingest ({exc})")
            continue
        version = result.get("version") or src.version
        writer.add_source(
            key, framework=src.framework, title=src.title, version=version, url=used_url, sha256=digest,
            license=src.license, retrieved_at=_now(), status="loaded", note=None,
        )
        src.sha256 = digest
        src.version = version
        report["sources"].append({**result, "version": version, "sha256": digest})

    report["attack_cross_bundle_links"] = resolve_cross_bundle_references(writer)
    report["cross_checks"] = _cross_check(writer)
    report["finished_at"] = _now()
    writer.commit({
        "build_report": report,
        "built_at": report["finished_at"],
        "d3fend_properties": getattr(writer, "d3fend_properties", {}),
        "d3fend_known_offensive_ids": getattr(writer, "d3fend_known_offensive_ids", []),
    })

    if db_path.exists() and keep_previous:
        db_path.replace(prev_path(db_path))
    tmp_path.replace(db_path)
    return report


def _cross_check(writer: GraphWriter) -> dict:
    """Annotate cross-framework edges whose targets are missing or revoked in the loaded data."""
    revoked_by: dict[str, list[str]] = {}
    for edge in writer.edges.values():
        if edge["rel"] == "revoked_by":
            revoked_by.setdefault(edge["src"], []).append(edge["dst"])
    stats: Counter = Counter()
    for edge in writer.edges.values():
        if edge["rel"] not in CROSS_RELATIONS:
            continue
        target = writer.nodes.get(edge["dst"])
        label = f"{edge['source']}:{edge['rel']}"
        if target is None:
            edge["detail"] = {**(edge["detail"] or {}), "target_missing": True}
            stats[f"{label}:target_missing"] += 1
        elif target["revoked"]:
            edge["detail"] = {**(edge["detail"] or {}), "target_revoked": True, "revoked_by": revoked_by.get(edge["dst"], [])}
            stats[f"{label}:target_revoked"] += 1
        elif target["deprecated"]:
            edge["detail"] = {**(edge["detail"] or {}), "target_deprecated": True}
            stats[f"{label}:target_deprecated"] += 1
    for key, count in sorted(stats.items()):
        writer.warnings.append(f"{count} cross-framework links ({key.rsplit(':', 1)[0]}) point at objects that are {key.rsplit(':', 1)[1].replace('target_', '')} in the loaded data")
    return dict(stats)
