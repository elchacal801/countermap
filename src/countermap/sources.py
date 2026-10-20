"""Upstream source registry, version resolution, download cache and lock files.

Every source is resolved to a concrete, versioned URL before download, so a build
can be reproduced from a lock file and verified by SHA-256. Every URL can be
overridden (environment variable or CLI) to point at an internal mirror or a
local file for air-gapped use.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from . import __version__

USER_AGENT = f"countermap/{__version__} (+https://github.com/elchacal801/countermap)"

ATTACK_TERMS = "MITRE ATT&CK Terms of Use (royalty-free, attribution required): https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"

DEFAULT_URLS = {
    "attack_index": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json",
    "f3": "https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-stix.json",
    "atlas_manifest": "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml",
    "atlas_base": "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/",
    # d3fend.mitre.org publishes each release under ontologies/d3fend/<version>/ (since 1.6.0 the
    # full mappings live only there; the old api/ontology/inference/ path returns 404).
    "d3fend_version": "https://d3fend.mitre.org/api/version.json",
    "d3fend_ontology": "https://d3fend.mitre.org/ontologies/d3fend/{version}/d3fend.ttl",
    "d3fend_ontology_latest": "https://d3fend.mitre.org/ontologies/d3fend.ttl",
    "d3fend_changelog": "https://raw.githubusercontent.com/d3fend/d3fend-ontology/develop/CHANGELOG.md",
    "d3fend_ontology_github": "https://raw.githubusercontent.com/d3fend/d3fend-ontology/{tag}/src/ontology/d3fend-protege.ttl",
    "d3fend_mappings": "https://d3fend.mitre.org/ontologies/d3fend/{version}/d3fend-full-mappings.json",
}

SOURCE_META = {
    "attack-enterprise": ("attack", "MITRE ATT&CK Enterprise", ATTACK_TERMS),
    "attack-mobile": ("attack", "MITRE ATT&CK Mobile", ATTACK_TERMS),
    "attack-ics": ("attack", "MITRE ATT&CK ICS", ATTACK_TERMS),
    "f3": ("f3", "MITRE Fight Fraud Framework (F3)", "Apache-2.0"),
    "atlas": ("atlas", "MITRE ATLAS", "Apache-2.0"),
    "d3fend-ontology": ("d3fend", "MITRE D3FEND ontology", "MIT (D3FEND Terms of Use also apply)"),
    "d3fend-mappings": ("d3fend", "MITRE D3FEND published inference mappings", "MIT (D3FEND Terms of Use also apply)"),
}

ALL_SOURCES = tuple(SOURCE_META)
# A complete build needs every source but the D3FEND published mappings; a build without one of these is degraded.
REQUIRED_SOURCES = tuple(k for k in ALL_SOURCES if k != "d3fend-mappings")


def url_override(key: str) -> str | None:
    env = "COUNTERMAP_URL_" + re.sub(r"[^A-Z0-9]", "_", key.upper())
    return os.environ.get(env)


def default_cache_dir() -> Path:
    base = os.environ.get("COUNTERMAP_CACHE") or os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    path = Path(base) / "countermap" if not os.environ.get("COUNTERMAP_CACHE") else Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_db_path() -> Path:
    return Path(os.environ.get("COUNTERMAP_DB") or default_cache_dir() / "countermap.db")


@dataclass
class ResolvedSource:
    key: str
    version: str | None
    url: str | None
    sha256: str | None = None
    framework: str = ""
    title: str = ""
    license: str = ""
    optional: bool = False
    fallbacks: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.key in SOURCE_META and not self.framework:
            self.framework, self.title, self.license = SOURCE_META[self.key]


class FetchError(RuntimeError):
    pass


def _is_local(ref: str) -> bool:
    return ref.startswith("file://") or not re.match(r"^[a-z][a-z0-9+.-]*://", ref)


def _local_path(ref: str) -> Path:
    if ref.startswith("file://"):
        return Path(urllib.parse.urlparse(ref).path)
    return Path(ref).expanduser()


def read_text(ref: str, timeout: float = 60) -> str:
    if _is_local(ref):
        return _local_path(ref).read_text(encoding="utf-8")
    req = urllib.request.Request(ref, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only by config)
            return resp.read().decode("utf-8")
    except Exception as exc:  # pragma: no cover - network dependent
        raise FetchError(f"could not read {ref}: {exc}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(ref: str, cache_dir: Path, timeout: float = 300) -> Path:
    """Return a local path for ``ref``, downloading into the cache if it is a URL."""
    if _is_local(ref):
        path = _local_path(ref)
        if not path.exists():
            raise FetchError(f"local source not found: {path}")
        return path
    name = hashlib.sha256(ref.encode()).hexdigest()[:16] + "-" + Path(urllib.parse.urlparse(ref).path).name
    dest = cache_dir / "raw" / name
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(ref, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            with tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as tmp:
                shutil.copyfileobj(resp, tmp)
                tmp_path = Path(tmp.name)
    except Exception as exc:  # pragma: no cover - network dependent
        raise FetchError(f"could not download {ref}: {exc}") from exc
    tmp_path.replace(dest)
    return dest


# -- resolution ----------------------------------------------------------------

def resolve_attack(attack_version: str | None = None) -> list[ResolvedSource]:
    index_url = url_override("attack_index") or DEFAULT_URLS["attack_index"]
    index = json.loads(read_text(index_url))
    out = []
    for collection in index["collections"]:
        name = collection["name"].lower()
        key = "attack-enterprise" if "enterprise" in name else "attack-mobile" if "mobile" in name else "attack-ics" if "ics" in name else None
        if key is None:
            continue
        versions = collection["versions"]
        chosen = versions[0] if attack_version is None else next(
            (v for v in versions if v["version"] == attack_version), None
        )
        if chosen is None:
            raise FetchError(f"ATT&CK version {attack_version} not found for {collection['name']}")
        out.append(ResolvedSource(key=key, version=chosen["version"], url=url_override(key) or chosen["url"]))
    return out


def resolve_f3() -> ResolvedSource:
    if url_override("f3"):
        return ResolvedSource(key="f3", version=None, url=url_override("f3"))
    latest = DEFAULT_URLS["f3"]
    bundle = json.loads(read_text(latest))
    version = next((o.get("x_mitre_version") for o in bundle.get("objects", [])
                    if o.get("type") == "x-mitre-collection"), None)
    if not version:
        return ResolvedSource(key="f3", version=None, url=latest)
    # CTID publishes each release as f3-stix-v<version>.json next to the moving f3-stix.json; pin to it.
    pinned = latest.rsplit("/", 1)[0] + f"/f3-stix-v{version}.json"
    return ResolvedSource(key="f3", version=str(version), url=pinned, fallbacks=[latest])


def resolve_atlas() -> ResolvedSource:
    if url_override("atlas"):
        return ResolvedSource(key="atlas", version=None, url=url_override("atlas"))
    manifest = yaml.safe_load(read_text(url_override("atlas_manifest") or DEFAULT_URLS["atlas_manifest"]))
    base = url_override("atlas_base") or DEFAULT_URLS["atlas_base"]
    for release in manifest:
        v6 = next((v for v in release["versions"] if str(v["format-version"]).startswith("6")), None)
        if v6:
            return ResolvedSource(key="atlas", version=str(release["release"]), url=urllib.parse.urljoin(base, v6["path"]))
    raise FetchError("no ATLAS release with format v6 found in manifest")


def d3fend_release() -> str | None:
    """The D3FEND release d3fend.mitre.org serves, falling back to the newest CHANGELOG entry."""
    try:
        version = json.loads(read_text(url_override("d3fend_version") or DEFAULT_URLS["d3fend_version"])).get("version")
        if version:
            return str(version)
    except (FetchError, ValueError, AttributeError):
        pass
    try:
        changelog = read_text(url_override("d3fend_changelog") or DEFAULT_URLS["d3fend_changelog"])
    except FetchError:
        return None
    match = re.search(r"^## Version - ([0-9][0-9.]*)", changelog, re.M)
    return match.group(1) if match else None


def resolve_d3fend() -> list[ResolvedSource]:
    version = d3fend_release()
    if version:
        ontology_url = DEFAULT_URLS["d3fend_ontology"].format(version=version)
        fallbacks = [DEFAULT_URLS["d3fend_ontology_github"].format(tag=version)]
        mappings_url = DEFAULT_URLS["d3fend_mappings"].format(version=version)
    else:
        # Without a release version there is no versioned mappings file to point at.
        ontology_url, fallbacks, mappings_url = DEFAULT_URLS["d3fend_ontology_latest"], [], None
    ontology = ResolvedSource(
        key="d3fend-ontology",
        version=version,
        url=url_override("d3fend-ontology") or ontology_url,
        fallbacks=fallbacks,
    )
    mappings = ResolvedSource(
        key="d3fend-mappings",
        version=version,
        url=url_override("d3fend-mappings") or mappings_url,
        optional=True,
    )
    return [ontology, mappings]


def resolve_all(attack_version: str | None = None, only: set[str] | None = None) -> list[ResolvedSource]:
    wanted = only or set(ALL_SOURCES)
    resolved: list[ResolvedSource] = []
    if wanted & {"attack-enterprise", "attack-mobile", "attack-ics"}:
        resolved += [s for s in resolve_attack(attack_version) if s.key in wanted]
    if "f3" in wanted:
        resolved.append(resolve_f3())
    if "atlas" in wanted:
        resolved.append(resolve_atlas())
    if wanted & {"d3fend-ontology", "d3fend-mappings"}:
        resolved += [s for s in resolve_d3fend() if s.key in wanted]
    return resolved


# -- lock files -------------------------------------------------------------------

def write_lock(path: Path, sources: list[ResolvedSource]) -> None:
    payload = {
        "generated_by": USER_AGENT,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "sources": [
            {k: v for k, v in asdict(s).items() if k in ("key", "version", "url", "sha256", "optional")}
            for s in sources
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def read_lock(path: Path) -> list[ResolvedSource]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [ResolvedSource(**{k: v for k, v in s.items()}) for s in data["sources"]]


def compare_to_lock(lock: list[ResolvedSource], latest: list[ResolvedSource]) -> list[dict]:
    """Report sources whose resolved version or URL differs from the lock."""
    locked = {s.key: s for s in lock}
    changes = []
    for s in latest:
        old = locked.get(s.key)
        if old is None:
            changes.append({"key": s.key, "change": "new-source", "latest": s.version})
            continue
        # Compare release versions when both sides know them. URLs alone are not a signal: the
        # lock may record a mirror or fallback URL for the same release.
        if old.version and s.version:
            changed = old.version != s.version
        else:
            changed = old.url != s.url
        if changed:
            changes.append({"key": s.key, "change": "new-version", "locked": old.version, "latest": s.version, "url": s.url})
    return changes
