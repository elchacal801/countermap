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


class RequiredSourceError(BuildError):
    """A required source could not be fetched or ingested (``build(allow_partial=True)`` builds without it)."""

    def __init__(self, key: str, message: str):
        super().__init__(message)
        self.key = key


PARTIAL = "required; built without it because of --allow-partial"


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
    allow_partial: bool = False,
    log=print,
) -> dict:
    """Build the database from ``sources`` into a temporary file, then swap it in.

    A required source that cannot be fetched or ingested raises RequiredSourceError; the temporary file is
    removed and the existing database is left as it was. With ``allow_partial`` the build records it instead and
    marks the database degraded. An optional source that fails is recorded and skipped. A SHA-256 mismatch
    against a lock always fails.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = db_path.with_name(db_path.name + ".building")
    writer = GraphWriter(tmp_path)
    report: dict = {"started_at": _now(), "countermap_version": __version__, "sources": []}
    try:
        _load(writer, sources, cache_dir, report, verify_hashes=verify_hashes, allow_partial=allow_partial, log=log)
        optional = {s.key: s.optional for s in sources}
        missing = [{"key": key, "status": s["status"], "required": not optional[key], "note": s.get("note")}
                   for key, s in writer.sources.items() if s["status"] != "loaded"]
        degraded = any(m["required"] for m in missing)
        if degraded:
            writer.warnings.append("degraded build (--allow-partial): required sources not loaded: " + ", ".join(
                f"{m['key']} ({m['status']})" for m in missing if m["required"]))
        report.update(degraded=degraded, missing_sources=missing)
        report["attack_cross_bundle_links"] = resolve_cross_bundle_references(writer)
        report["cross_checks"] = _cross_check(writer)
        report["finished_at"] = _now()
        writer.commit({
            "build_report": report,
            "built_at": report["finished_at"],
            "degraded": degraded,
            "missing_sources": missing,
            "d3fend_properties": getattr(writer, "d3fend_properties", {}),
            "d3fend_known_offensive_ids": getattr(writer, "d3fend_known_offensive_ids", []),
        })
    except BaseException:
        writer.conn.close()
        tmp_path.unlink(missing_ok=True)
        raise

    if db_path.exists() and keep_previous:
        db_path.replace(prev_path(db_path))
    tmp_path.replace(db_path)
    return report


def _load(writer: GraphWriter, sources: list[ResolvedSource], cache_dir: Path, report: dict, *,
          verify_hashes: bool, allow_partial: bool, log) -> None:
    """Fetch, verify and ingest each source in ORDER into ``writer``, recording each one's status."""
    by_key = {s.key: s for s in sources}
    for key in ORDER:
        src = by_key.get(key)
        if src is None:
            continue
        if key == "d3fend-mappings" and not hasattr(writer, "d3fend_iri_to_id"):
            # The mappings name D3FEND techniques by ontology class, so they cannot be read without it.
            writer.add_source(
                key, framework=src.framework, title=src.title, version=src.version, url=src.url,
                license=src.license, retrieved_at=_now(), status="unavailable",
                note="skipped: the D3FEND ontology was not loaded",
            )
            writer.warnings.append("d3fend-mappings skipped: the D3FEND ontology was not loaded")
            log(f"  ! {key}: skipped, the D3FEND ontology was not loaded ({'optional' if src.optional else PARTIAL})")
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
            if not src.optional and not allow_partial:
                log(f"  ! {key}: unavailable (required)")
                raise RequiredSourceError(key, f"required source {key} could not be fetched: {note}")
            log(f"  ! {key}: unavailable ({'optional' if src.optional else PARTIAL})")
            continue

        digest = sha256_file(path)
        if verify_hashes and src.sha256 and src.sha256 != digest:
            raise BuildError(
                f"{key}: SHA-256 mismatch against lock (expected {src.sha256[:12]}, got {digest[:12]}). "
                "Upstream changed. Review it, then run `countermap lock` to accept."
            )

        log(f"  - ingesting {key} from {used_url}")
        ingest = {
            "f3": ingest_f3, "atlas": ingest_atlas,
            "d3fend-ontology": ingest_d3fend_ontology, "d3fend-mappings": ingest_d3fend_mappings,
        }.get(key, ingest_attack)
        try:
            result = ingest(writer, path, key)
        except Exception as exc:  # noqa: BLE001 - any parser error on upstream data (BadSyntax, YAMLError, ...)
            reason = str(exc) if isinstance(exc, (ValueError, KeyError, TypeError)) else f"{type(exc).__name__}: {exc}"
            if not src.optional and not allow_partial:
                raise RequiredSourceError(key, f"{key}: could not ingest {used_url}: {reason}") from exc
            # Drop whatever the parser stored before it failed, so a failed source contributes nothing.
            writer.nodes = {k: n for k, n in writer.nodes.items() if n["source"] != key}
            writer.edges = {k: e for k, e in writer.edges.items() if e["source"] != key}
            writer.add_source(
                key, framework=src.framework, title=src.title, version=src.version, url=used_url,
                sha256=digest, license=src.license, retrieved_at=_now(), status="failed", note=reason,
            )
            writer.warnings.append(f"{key} failed to ingest and was skipped: {reason}")
            log(f"  ! {key}: failed to ingest ({'optional' if src.optional else PARTIAL}): {reason}")
            continue
        version = result.get("version") or src.version
        writer.add_source(
            key, framework=src.framework, title=src.title, version=version, url=used_url, sha256=digest,
            license=src.license, retrieved_at=_now(), status="loaded", note=None,
        )
        src.sha256 = digest
        src.version = version
        report["sources"].append({**result, "version": version, "sha256": digest})


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
