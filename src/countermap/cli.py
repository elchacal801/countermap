"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

from . import __version__
from .sources import (
    ALL_SOURCES,
    FetchError,
    compare_to_lock,
    default_cache_dir,
    default_db_path,
    read_lock,
    resolve_all,
    write_lock,
)


def _utf8_stdio() -> None:
    """Write UTF-8 whatever the locale says.

    On Windows, piped or redirected output defaults to the ANSI code page (cp1252),
    which cannot encode names such as "Operation AkaiRyū" and aborted mid-JSON.
    """
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
        if encoding != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def _print(data) -> None:
    try:
        if isinstance(data, str):
            sys.stdout.write(data if data.endswith("\n") else data + "\n")
        else:
            json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
            sys.stdout.write("\n")
        sys.stdout.flush()
    except BrokenPipeError:  # output piped into head and closed early
        sys.stderr.close()


def _overrides(values: list[str] | None) -> dict[str, str]:
    out = {}
    for item in values or []:
        if "=" not in item:
            raise SystemExit(f"--source expects KEY=URL_OR_PATH, got {item!r}")
        key, ref = item.split("=", 1)
        if key not in ALL_SOURCES:
            raise SystemExit(f"unknown source {key!r}; choose from {', '.join(ALL_SOURCES)}")
        out[key] = ref
    return out


def _resolve(args) -> list:
    if getattr(args, "lock", None):
        sources = read_lock(Path(args.lock))
    else:
        only = set(args.only.split(",")) if getattr(args, "only", None) else None
        sources = resolve_all(attack_version=getattr(args, "attack_version", None), only=only)
    for key, ref in _overrides(getattr(args, "source", None)).items():
        for s in sources:
            if s.key == key:
                s.url, s.sha256, s.fallbacks = ref, None, []
    return sources


D3FEND_MISSING = ('Without D3FEND, countermeasure results say "unavailable" (not empty) until a complete build '
                  "succeeds.")


def cmd_build(args) -> int:
    from .ingest import BuildError, RequiredSourceError, build

    db = Path(args.db or default_db_path())
    try:
        sources = _resolve(args)
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    # A lock that leaves out a required source fails like an unreachable one. An explicit --only subset is the
    # user's choice: it builds, and the database is marked degraded.
    subset = bool(getattr(args, "only", None)) and not args.lock
    absent_note = (f"not in the lock file {args.lock}" if args.lock else
                   "not selected with --only" if subset else "not in the resolved upstream sources")
    print(f"Building {db}")
    try:
        report = build(db, sources, Path(args.cache or default_cache_dir()), verify_hashes=bool(args.lock),
                       allow_partial=args.allow_partial, subset=subset, absent_note=absent_note,
                       log=lambda m: print(m, file=sys.stderr))
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if isinstance(exc, RequiredSourceError):
            print("The existing database, if any, is unchanged. If this network cannot reach the source (a proxy or "
                  "firewall, for example), point --source at a mirror or a local copy, or rerun with --allow-partial "
                  "to build without it: the database is then marked degraded and 'countermap info' lists what is "
                  "missing." + (" " + D3FEND_MISSING if any(k.startswith("d3fend") for k in exc.keys) else ""),
                  file=sys.stderr)
        return 3
    if report["degraded"]:
        required = [m for m in report["missing_sources"] if m["required"]]
        print(f"warning: {'--allow-partial' if args.allow_partial else '--only'}: the database is degraded. "
              "Required sources not loaded: "
              + ", ".join(f"{m['key']} ({m['status']})" for m in required) + "."
              + (" " + D3FEND_MISSING if any(m["key"].startswith("d3fend") for m in required) else ""),
              file=sys.stderr)
    for s in report["sources"]:
        print(f"  {s['source']:<18} {str(s.get('version')):<10} sha256:{s['sha256'][:12]}")
    if args.write_lock:
        write_lock(Path(args.write_lock), sources)
        print(f"Wrote lock file {args.write_lock}")
    from .query import Countermap

    for w in Countermap(db).datasets()["warnings"]:
        print(f"  warning: {w}")
    return 0


def cmd_lock(args) -> int:
    from .sources import fetch, sha256_file

    sources = _resolve(args)
    cache = Path(args.cache or default_cache_dir())
    for s in sources:
        try:
            if not s.url:
                raise FetchError(f"{s.key}: no URL could be resolved")
            path = fetch(s.url, cache)
            s.sha256 = sha256_file(path)
        except FetchError:
            ok = False
            for fb in s.fallbacks:
                try:
                    s.sha256, s.url = sha256_file(fetch(fb, cache)), fb
                    ok = True
                    break
                except FetchError:
                    continue
            if not ok:
                print(f"  ! {s.key}: could not fetch; recorded without hash", file=sys.stderr)
    write_lock(Path(args.output), sources)
    print(f"Wrote {args.output}")
    return 0


def cmd_check_updates(args) -> int:
    lock_path = Path(args.lock)
    if not lock_path.is_file():
        print(f"error: no lock file at {lock_path}. check-updates compares the latest upstream releases with a lock "
              "file. Pass --lock PATH (for example the sources.lock.json from the Countermap repository), or write "
              "one now with 'countermap lock -o sources.lock.json' and check against it later.", file=sys.stderr)
        return 2
    lock = read_lock(lock_path)
    latest = resolve_all()
    changes = compare_to_lock(lock, latest)
    _print({"changes": changes})
    return 10 if changes else 0


def cmd_serve(args) -> int:
    import os

    if args.db:
        os.environ["COUNTERMAP_DB"] = str(Path(args.db).resolve())
    from .server import main as serve

    serve()
    return 0


def _db(args):
    from .query import Countermap

    return Countermap(Path(args.db or default_db_path()))


def cmd_query(args) -> int:
    from .query import NotFound

    c = _db(args)
    try:
        if args.command == "lookup":
            out = c.lookup(args.ref)
        elif args.command == "search":
            out = c.search(" ".join(args.query), framework=args.framework, kind=args.kind, limit=args.limit)
        elif args.command == "context":
            out = c.technique_context(args.ref)
        elif args.command == "counter":
            out = c.countermeasures(args.ref, tactic=args.tactic)
        elif args.command == "actor":
            out = c.actor_techniques(args.ref, include_software=args.with_software)
        elif args.command == "gaps":
            out = c.coverage_gaps(args.refs)
        elif args.command == "coverage":
            out = c.telemetry_coverage(log_sources=args.log_source, data_components=args.data_component,
                                       platform=args.platform, techniques=args.technique, actor=args.actor,
                                       include_software=args.with_software, limit=args.limit,
                                       layer=bool(args.layer), domain=args.domain)
        else:
            out = c.datasets()
    except NotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    if getattr(args, "layer", None) and "navigator" in out:
        for p in _write_layers(Path(args.layer), out.pop("navigator")["layers"]):
            print(f"wrote {p}", file=sys.stderr)
    _print(out)
    return 0


SIGMA_TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


SIGMA_MAX_BYTES = 1024 * 1024
SIGMA_MAX_NESTING = 100
_SCALAR_STARTS = frozenset(" \t\r\n:,[{-?")  # a quote after one of these opens a quoted string


class _NestingTooDeep(ValueError):
    pass


def _nesting_depth(text: str) -> int:
    """The deepest ``[`` and ``{`` nesting in YAML text, in one linear pass.

    Brackets in quoted strings and in comments do not count. A quote opens a string only where a scalar can
    start, so the apostrophe in "it's" does not. A cheap approximation of YAML, enough to refuse hostile files
    before the parser spends a minute recursing into them.
    """
    depth = deepest = 0
    i, n, prev = 0, len(text), "\n"
    while i < n:
        ch = text[i]
        if ch in "'\"" and prev in _SCALAR_STARTS:
            j = i + 1
            while j < n:
                if ch == '"' and text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch:
                    if ch == "'" and j + 1 < n and text[j + 1] == "'":  # '' is an escaped quote
                        j += 2
                        continue
                    break
                j += 1
            i, prev = j + 1, ch
            continue
        if ch == "#" and prev in " \t\r\n":
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth = max(0, depth - 1)
        prev = ch
        i += 1
    return deepest


def _is_link(path: str) -> bool:
    """A symlink, or on Windows any reparse point such as a junction (which os.walk would otherwise follow)."""
    try:
        st = os.lstat(path)
    except OSError:
        return True  # cannot tell: do not descend
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _sigma_rules(path: str) -> tuple[int, set[str], int]:
    """Rules, technique IDs and rules with technique tags in one Sigma file. May raise anything."""
    import yaml

    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    # Deeply nested YAML costs the pure-Python parser about a minute of CPU before a RecursionError. The C
    # loader (yaml.CSafeLoader) is not a way out: it kills the interpreter on the same input.
    if text.count("[") + text.count("{") > SIGMA_MAX_NESTING and _nesting_depth(text) > SIGMA_MAX_NESTING:
        raise _NestingTooDeep()
    docs = list(yaml.safe_load_all(text))
    rules, tagged, ids = 0, 0, set()
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        rules += 1
        tags = doc.get("tags") if isinstance(doc.get("tags"), list) else []
        found = {m.group(1).upper() for t in tags
                 if isinstance(t, str) and (m := SIGMA_TECHNIQUE_TAG.fullmatch(t.strip()))}
        if found:
            tagged += 1
            ids |= found
    return rules, ids, tagged


def sigma_techniques(directory: Path) -> tuple[list[str], dict]:
    """ATT&CK technique IDs from the ``attack.tNNNN`` tags of the Sigma rules under ``directory``.

    This lives in the CLI on purpose, not in the MCP server: the server's tools take IDs and never read a path
    an agent names, so an agent steered by injected text cannot use them to read files. YAML is parsed with
    ``yaml.safe_load_all``, which builds plain data and never runs code.

    One bad file never stops the run: any error while reading or parsing a file skips it, counted under its
    exception type, and files over 1 MiB are skipped unread. The walk never follows symlinks or Windows
    junctions (so a link loop cannot make it run forever), and a file reached twice is read once.
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise FileNotFoundError(f"no such directory: {directory}")
    found: set[str] = set()
    reasons: dict[str, int] = {}
    stats: dict = {"files": 0, "rules": 0, "rules_with_technique_tags": 0, "skipped": 0, "links_not_followed": 0,
                   "unreadable_directories": 0}
    seen: set[str] = set()

    def skip(reason: str) -> None:
        stats["skipped"] += 1
        reasons[reason] = reasons.get(reason, 0) + 1

    def unreadable(_exc: OSError) -> None:
        stats["unreadable_directories"] += 1

    for root, dirs, files in os.walk(directory, followlinks=False, onerror=unreadable):
        followed = []
        for name in sorted(dirs):
            if _is_link(os.path.join(root, name)):
                stats["links_not_followed"] += 1
            else:
                followed.append(name)
        dirs[:] = followed
        for name in sorted(files):
            if not name.lower().endswith((".yml", ".yaml")):
                continue
            path = os.path.join(root, name)
            if os.path.islink(path):
                stats["links_not_followed"] += 1
                continue
            real = os.path.normcase(os.path.realpath(path))
            if real in seen:
                continue
            seen.add(real)
            stats["files"] += 1
            try:
                if os.path.getsize(path) > SIGMA_MAX_BYTES:
                    skip("over 1 MiB")
                    continue
                rules, ids, tagged = _sigma_rules(path)
            except Exception as exc:  # noqa: BLE001 - a hostile or broken file must never abort the run
                skip("nesting too deep" if isinstance(exc, _NestingTooDeep) else type(exc).__name__)
                continue
            stats["rules"] += rules
            stats["rules_with_technique_tags"] += tagged
            found |= ids
    stats["skipped_reasons"] = dict(sorted(reasons.items()))
    return sorted(found), stats


def cmd_rules_coverage(args) -> int:
    from .query import NotFound

    sigma = None
    if args.sigma:
        techniques, sigma = sigma_techniques(Path(args.sigma))
        sigma["techniques"] = len(techniques)
    else:
        techniques = args.technique
    try:
        out = _db(args).rule_coverage(techniques, scope_actors=args.actor, platform=args.platform, tactics=args.tactic,
                                      domain=args.domain, limit=args.limit, layer=bool(args.layer))
    except NotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    if sigma is not None:
        out = {"sigma": sigma, **out}
    if args.layer and "navigator" in out:
        for p in _write_layers(Path(args.layer), out.pop("navigator")["layers"]):
            print(f"wrote {p}", file=sys.stderr)
    _print(out)
    return 0


def _write_text(path: Path, text: str) -> None:
    """Write UTF-8 text with LF line endings on every platform (no CRLF translation on Windows)."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _write_layers(path: Path, layers: dict) -> list[Path]:
    """Write Navigator layers: one domain to ``path``, several to ``<stem>.<domain><suffix>`` beside it."""
    written = []
    for domain, layer in layers.items():
        p = path if len(layers) == 1 else path.with_name(f"{path.stem}.{domain}{path.suffix or '.json'}")
        p.parent.mkdir(parents=True, exist_ok=True)
        _write_text(p, json.dumps(layer, indent=2, ensure_ascii=False))
        written.append(p)
    return written


def cmd_render(args) -> int:
    from .emit import RenderError, render
    from .query import NotFound

    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    formats = args.format or None
    try:
        out = render(spec, _db(args), formats, scope=args.scope)
    except (NotFound, RenderError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    stem = args.name or Path(args.spec).stem
    written = []
    if "cad" in out:
        p = outdir / f"{stem}.d3fend-cad.json"
        _write_text(p, json.dumps(out["cad"], indent=2))
        written.append(p)
    if "attack_flow" in out:
        p = outdir / f"{stem}.attack-flow.json"
        _write_text(p, json.dumps(out["attack_flow"], indent=2))
        written.append(p)
    if "mermaid" in out:
        p = outdir / f"{stem}.mmd"
        _write_text(p, out["mermaid"])
        written.append(p)
    for domain, layer in (out.get("navigator") or {}).items():
        p = outdir / f"{stem}.navigator.{domain}.json"
        _write_text(p, json.dumps(layer, indent=2))
        written.append(p)
    for p in written:
        print(p)
    for w in out["warnings"]:
        print(f"warning: {w}", file=sys.stderr)
    return 0


def cmd_diff(args) -> int:
    from .diff import diff_snapshots

    _print(diff_snapshots(Path(args.old), Path(args.new), framework=args.framework or None, kind=args.kind, limit=args.limit))
    return 0


def cmd_calibrate(args) -> int:
    from .emit.cad import calibrate_from_export, calibration_path

    cal = calibrate_from_export(json.loads(Path(args.exported).read_text(encoding="utf-8")))
    path = calibration_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cal, indent=2), encoding="utf-8")
    print(f"Saved CAD calibration to {path}")
    _print(cal)
    return 0


DESCRIPTION = """\
Countermap: a local, read-only knowledge graph of MITRE ATT&CK® (Enterprise,
Mobile, ICS), D3FEND, ATLAS and F3, with provenance on every cross-framework
link. Build the database once with "countermap build", then query it from the
shell or serve it to MCP clients with "countermap serve"."""

EPILOG = """\
examples:
  countermap build                          fetch the latest releases and build
  countermap lookup "Cozy Bear"             any object by ID, name or alias
  countermap counter T1539                  D3FEND countermeasures for T1539
  countermap render scenario.json -o out/   CAD, Attack Flow, Navigator, Mermaid
  countermap serve                          the read-only MCP server over stdio

Run "countermap COMMAND --help" for the options of one command.
Documentation: https://github.com/elchacal801/countermap"""


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()  # before parsing, so --help and usage errors are UTF-8 too
    p = argparse.ArgumentParser(prog="countermap", description=DESCRIPTION, epilog=EPILOG,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"countermap {__version__}")
    p.add_argument("--db", help="database path (default: $COUNTERMAP_DB or the user cache)")
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="download (or read mirrors/local files) and build the database")
    b.add_argument("--lock", help="build exactly the sources in this lock file and verify SHA-256")
    b.add_argument("--write-lock", help="write the resolved sources and hashes to this lock file")
    b.add_argument("--attack-version", help="pin ATT&CK to a version, e.g. 19.2")
    b.add_argument("--only", help="build only these comma-separated source keys: " + ",".join(ALL_SOURCES)
                   + "; leaving out a required source marks the database degraded")
    b.add_argument("--source", action="append", help="override a source: KEY=URL_OR_PATH (repeatable)")
    b.add_argument("--cache", help="download cache directory")
    b.add_argument("--allow-partial", action="store_true",
                   help="build even if required sources cannot be fetched or ingested, or the lock file leaves them "
                        "out; the database is marked "
                        "degraded and 'countermap info' lists the missing sources")
    b.set_defaults(func=cmd_build)

    lk = sub.add_parser("lock", help="resolve the latest upstream versions and write a lock file")
    lk.add_argument("-o", "--output", default="sources.lock.json")
    lk.add_argument("--attack-version")
    lk.add_argument("--only")
    lk.add_argument("--source", action="append")
    lk.add_argument("--cache")
    lk.set_defaults(func=cmd_lock)

    cu = sub.add_parser("check-updates", help="compare upstream to a lock file; exit 10 when updates exist")
    cu.add_argument("--lock", default="sources.lock.json",
                    help="the lock file to compare against (default: sources.lock.json in the current directory)")
    cu.set_defaults(func=cmd_check_updates)

    sv = sub.add_parser("serve", help="run the read-only MCP server over stdio")
    sv.set_defaults(func=cmd_serve)

    for name, helptext in (("lookup", "look up an object"), ("context", "technique context"),
                           ("counter", "D3FEND countermeasures for a technique"), ("actor", "techniques for an actor")):
        q = sub.add_parser(name, help=helptext)
        q.add_argument("ref")
        if name == "counter":
            q.add_argument("--tactic")
        if name == "actor":
            q.add_argument("--with-software", action="store_true")
        q.set_defaults(func=cmd_query)
    s = sub.add_parser("search", help="full-text search")
    s.add_argument("query", nargs="+")
    s.add_argument("--framework")
    s.add_argument("--kind")
    s.add_argument("--limit", type=int, default=10)
    s.set_defaults(func=cmd_query)
    g = sub.add_parser("gaps", help="coverage gaps for a list of techniques")
    g.add_argument("refs", nargs="+")
    g.set_defaults(func=cmd_query)
    cv = sub.add_parser("coverage", help="what your log sources can detect (by ATT&CK analytics) and where you are blind")
    cv.add_argument("--log-source", action="append",
                    help='a log source you collect, optionally with a channel: "WinEventLog:Sysmon EventCode=10" (repeatable)')
    cv.add_argument("--data-component", action="append", help="a data component you collect, ID or name (repeatable)")
    target = cv.add_mutually_exclusive_group()
    target.add_argument("--actor", help="a group, software or campaign whose techniques to check")
    target.add_argument("--technique", action="append", help="a technique to check (repeatable)")
    cv.add_argument("--with-software", action="store_true", help="with --actor, add techniques of its software")
    cv.add_argument("--platform", help="only analytics (and, with no target, techniques) for this platform")
    cv.add_argument("--domain", choices=["enterprise-attack", "mobile-attack", "ics-attack"],
                    help="only techniques of this ATT&CK domain (default: all three)")
    cv.add_argument("--limit", type=int, default=50, help="techniques listed per class")
    cv.add_argument("--layer", help="also write a Navigator coverage layer to this file")
    cv.set_defaults(func=cmd_query)
    rc = sub.add_parser("rules-coverage", help="what your detection rules cover, and the gaps ranked by threat-group use")
    rules = rc.add_mutually_exclusive_group(required=True)
    rules.add_argument("--technique", action="append", help="an ATT&CK technique ID your rules map to (repeatable)")
    rules.add_argument("--sigma", help="a directory of Sigma rules whose attack.tNNNN tags to read (parsed, never run)")
    rc.add_argument("--actor", action="append", help="scope to this group, software or campaign's techniques (repeatable)")
    rc.add_argument("--platform", help="scope to techniques for this platform")
    rc.add_argument("--tactic", action="append", help="scope to this tactic, by name or ID (repeatable)")
    rc.add_argument("--domain", default="enterprise-attack", choices=["enterprise-attack", "mobile-attack", "ics-attack"])
    rc.add_argument("--limit", type=int, default=50, help="gaps and covered techniques listed")
    rc.add_argument("--layer", help="also write a Navigator coverage layer to this file")
    rc.set_defaults(func=cmd_rules_coverage)
    d = sub.add_parser("info", help="datasets, versions and build warnings")
    d.set_defaults(func=cmd_query)

    r = sub.add_parser("render", help="render a scenario spec to CAD, Attack Flow, Mermaid and Navigator files")
    r.add_argument("spec")
    r.add_argument("-o", "--out", default=".")
    r.add_argument("--name")
    r.add_argument("--format", action="append", choices=["cad", "attack_flow", "mermaid", "navigator"])
    r.add_argument("--scope", default="incident",
                   choices=["incident", "campaign", "threat-actor", "malware", "emulation-plan", "attack-tree", "other"])
    r.set_defaults(func=cmd_render)

    df = sub.add_parser("diff", help="compare two database snapshots")
    df.add_argument("old")
    df.add_argument("new")
    df.add_argument("--framework", default="attack")
    df.add_argument("--kind")
    df.add_argument("--limit", type=int, default=50)
    df.set_defaults(func=cmd_diff)

    cal = sub.add_parser("calibrate-cad", help="learn CAD handle ids and schema version from a graph exported by D3FEND CAD")
    cal.add_argument("exported")
    cal.set_defaults(func=cmd_calibrate)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
