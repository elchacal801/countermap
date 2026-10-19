# Countermap architecture

This document describes how Countermap is built and how to maintain it: its modules and data flow, the provenance rules every result follows, the upstream sources it reads, how to run it, and how to keep it current. The [README](../README.md) is the introduction and covers installation and everyday use.

Countermap builds a local SQLite knowledge graph from four MITRE knowledge bases, MITRE ATT&CK® (Enterprise, Mobile and ICS), D3FEND, ATLAS and the Fight Fraud Framework (F3), and serves it read-only to AI agents over MCP and to people through a command-line interface. From one small scenario spec it renders four validated output formats: D3FEND CAD graphs, Attack Flow 2.0 STIX bundles, ATT&CK Navigator layers and Mermaid diagrams. Every cross-framework link says whether MITRE published it, whether Countermap derived it (with the path it was derived through), or whether an analyst asserted it. Coverage gaps are reported as gaps, never filled with guesses.

## Architecture

```
upstream (GitHub raw, d3fend.mitre.org, or local mirror files)
   |  sources.py: resolve versions -> lock file -> fetch + SHA-256 -> cache
   v
ingest/  attack.py  f3.py  atlas.py  d3fend.py      (one parser per framework)
   |  ingest/__init__.py: build into a temp DB, cross-check, atomic swap, keep .prev snapshot
   v
SQLite (db.py): nodes, edges (official only), sources, meta, FTS5 search index
   |
query.py  (read-only, thread-safe, provenance-aware)      diff.py (snapshot comparison)
   |
scenario.py (spec validation + ID resolution) -> emit/ (cad, attack_flow, navigator, mermaid, validate)
   |
server.py (MCP, 14 read-only tools)      cli.py (same capabilities from the shell)
```

| Module | Responsibility |
|---|---|
| `sources.py` | Upstream registry, version resolution, mirrors and overrides, download cache, lock files, update detection |
| `ingest/attack.py` | ATT&CK STIX 2.1: techniques, tactics, groups, software, campaigns (with first and last seen dates and their citations), mitigations, detection strategies, analytics (with their log-source references and tunable fields), data components, ICS assets and every relationship type |
| `ingest/f3.py` | F3 STIX; keeps F3 objects in the `f3:` namespace and links reused ATT&CK IDs |
| `ingest/atlas.py` | ATLAS v6 YAML, including the official ATT&CK references and case-study steps |
| `ingest/d3fend.py` | D3FEND ontology (TTL) and the published inference mappings (JSON) |
| `db.py` | Schema, relation vocabulary, graph writer |
| `query.py` | Lookups, search, technique context, countermeasures, crosswalk, actor analysis, coverage gaps, telemetry and rule coverage |
| `scenario.py` | Scenario spec model (pydantic), validation, ID resolution, countermeasure selection |
| `emit/` | Renderers plus offline validation against the vendored Attack Flow, STIX and CAD schemas |
| `server.py` | MCP server: tool definitions and error containment |
| `cli.py` | Command-line interface |

**ID namespaces.** Every node is `framework:ID`: `attack:T1003.001`, `f3:T1056`, `atlas:AML.T0051`, `d3fend:D3-MFA`. Three upstream quirks are handled explicitly and reported as build warnings:

- **Legacy ATT&CK mitigations** reuse technique IDs. They are stored as `attack:mitigation:T1033` so they never shadow the technique.
- **ATT&CK ICS** publishes a deprecated EKANS under S0017, which Enterprise uses for BISCUIT. It is stored as `attack:S0017@ics-attack`.
- **D3FEND IDs on more than one class.** D3FEND 1.6.0 assigns 27 IDs to more than one ontology class. The extra classes are stored as `ID@ClassName`.

## Provenance rules

These rules define what Countermap stores and how it labels what it returns. Every change to the code should preserve them.

1. **Stored edges are official only.** Each one came from an upstream publication:
   - ATT&CK relationships
   - ATLAS `attack-reference` fields
   - F3's reuse of ATT&CK IDs
   - D3FEND's published inference output

   Every edge records its source dataset.
2. **Derived links are computed at query time**, labeled `provenance: derived`, and carry a `via` path. The derivations are:
   - parent technique or sub-technique
   - a revoked ATT&CK ID that ATT&CK now points to this technique
   - an F3 or ATLAS link to ATT&CK
   - software used by an actor
3. **Analyst assertions** (countermeasures listed explicitly in a scenario that D3FEND does not map to that step) are labeled `analyst` and drawn as such.
4. **Empty is not "safe".** A countermeasure query with no results says either "no D3FEND mapping" or "the loaded D3FEND release predates this technique". If the mappings are missing or failed, it says "unavailable, not empty".
5. **No inference engine.** Countermap does not compute its own D3FEND countermeasure links. If MITRE has not published a mapping, the link does not exist here.
6. **Computed results say so.** The coverage classes and the gap ranking below are Countermap's arithmetic over MITRE's data, not MITRE's statements. Each result carries a `basis` note that says what was computed and from what.

### Coverage logic

**Telemetry coverage** (`telemetry_coverage`, `countermap coverage`) matches the telemetry you collect against the log-source references MITRE publishes on each ATT&CK analytic (`x_mitre_log_source_references`: a log source name, a channel and a data component).

- **Matching.** A reference matches when its data component is one you named, or its log source name is one you named (case-insensitive) and its channel is collected. A name without a channel collects every channel. A channel of "None" in MITRE's data counts as no channel. `EventCode=` lists are compared as sets, so `EventCode=4663, 4656` needs both codes; having one of them counts as partial.
- **Inputs that match nothing are warned about:** a log source name no analytic uses, a name and channel pair no analytic uses (the warning lists the channels that exist), and a data component name passed as a log source.
- **References across bundles are resolved.** An analytic's data-component reference is looked up in every loaded ATT&CK bundle, after all of them have loaded, so the result does not depend on load order. In ATT&CK 20.0 this resolves 12 references from ICS analytics to data components that only the Enterprise bundle publishes. A reference no loaded bundle publishes becomes a build warning (none in 20.0).
- **Classes.** With a platform, only that platform's analytics count.
  - `covered`: at least one analytic has all of its references matched.
  - `partial`: some analytic has at least one reference matched (or some of its event codes), but none is complete.
  - `blind`: the technique has analytics, but none uses your telemetry. An analytic with no log-source references (73 in ATT&CK 20.0, as in MITRE's data) can never be covered.
  - `no_analytic_for_platform`: the technique has detection strategies, but none of their analytics is for the platform. Without this class those techniques would read as blind.
  - `no_detection_strategy`: ATT&CK links no detection strategy to the technique.
- **Target.** A technique list, an actor's techniques (as `actor_techniques`, optionally through its software), or every active technique on the platform, in one ATT&CK domain or all three (the default). The result names the domains, and lists requested techniques outside them.
- **Inputs and caps.** Repeated inputs are taken once before any cap, and every cut is noted in the result. The MCP tool returns a Navigator layer for up to 120 techniques; for more it points to `countermap coverage ... --layer FILE`, which has no limit. The same applies to rule coverage.

**Rule coverage** (`rule_coverage`, `countermap rules-coverage`) takes the ATT&CK IDs a ruleset is mapped to. Revoked IDs are followed to their replacement with a warning.

- **Scope.** The domain's active techniques, filtered by platform and tactic, or only the techniques of `scope_actors` (with their software).
- **Status.**
  - `covered`: the technique's own ID is listed.
  - `partial`: its parent is listed ("covered via parent"), or it is a parent with some of its sub-techniques listed. A parent with all of its sub-techniques listed but not its own ID is also partial, because Countermap does not claim coverage for an ID the ruleset does not list.
  - `uncovered`: everything else.
- **Ranking.** Uncovered gaps, then partial ones, by the number of active groups ATT&CK links to the technique directly, or through software they use (the latter derived by Countermap). Each entry gives the total and the direct count (`groups.direct`), and marks each example group direct or derived; the ranking uses the total. Ties go to the campaign count (counted the same way), then the technique ID. With `scope_actors`, the number of those actors that use the technique comes first, then the overall group count, the campaign count and the technique ID, so a single scope actor still gets a meaningful order. A group count reflects ATT&CK's links (direct, or derived through software), not prevalence in the wild.
- **Sigma.** The CLI can read the IDs from a folder of Sigma rules (`attack.tNNNN` tags, parsed with `yaml.safe_load_all`). It never follows symlinks or junctions, reads each file once, skips files over 1 MiB or nested more than 100 brackets deep (found by a quick scan before parsing), and skips any file that fails to read or parse, counting it under its exception type. The MCP tool takes IDs only and never reads paths.

## Upstream sources

| Key | Upstream | License | Cadence | Pinning |
|---|---|---|---|---|
| `attack-enterprise`, `attack-mobile`, `attack-ics` | `mitre-attack/attack-stix-data` via `index.json` | ATT&CK Terms of Use | Two major releases a year (April, October) plus minor releases | Versioned file + SHA-256 |
| `f3` | `center-for-threat-informed-defense/fight-fraud-framework` `public/f3-stix-v<version>.json` | Apache-2.0 | Irregular | Versioned file + SHA-256 |
| `atlas` | `mitre-atlas/atlas-data` `dist/manifest.yaml` -> newest v6 YAML | Apache-2.0 | Monthly | Versioned file + SHA-256 |
| `d3fend-ontology` | `d3fend.mitre.org/ontologies/d3fend/<version>/d3fend.ttl` (release from `d3fend.mitre.org/api/version.json`, else the CHANGELOG), falling back to the tagged release on GitHub | MIT + D3FEND Terms of Use | Roughly monthly | Versioned file + SHA-256 |
| `d3fend-mappings` | `d3fend.mitre.org/ontologies/d3fend/<version>/d3fend-full-mappings.json` (until 1.5.0 also at the now-removed `api/ontology/inference/` path) | MIT + D3FEND Terms of Use | With D3FEND releases | Versioned file + SHA-256 |

Upstream data is downloaded at build time and never committed. The repository vendors only three things, all listed in `NOTICE`:

- the Attack Flow schema
- the OASIS STIX common schemas
- the CAD schema

The 12 OASIS schemas are BSD-3-Clause, so the package license is `Apache-2.0 AND BSD-3-Clause`, and the OASIS license text ships with the package as `LICENSES/BSD-3-Clause-OASIS.txt` (copied verbatim from `oasis-open/cti-stix2-json-schemas`).

Data problems that the build finds in the upstream releases, such as links to revoked or missing objects, are reported to the upstream projects, for example in [fight-fraud-framework#33](https://github.com/center-for-threat-informed-defense/fight-fraud-framework/issues/33), [atlas-data#32](https://github.com/mitre-atlas/atlas-data/issues/32) and [d3fend-ontology#709](https://github.com/d3fend/d3fend-ontology/issues/709).

## Running Countermap

From PyPI: `pip install countermap`, `pipx install countermap`, or `uvx countermap <command>` without installing. From a clone:

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q                                            # offline suite
countermap build                                    # latest upstream
countermap build --lock sources.lock.json           # pinned releases
countermap info                                     # versions, counts, build warnings
countermap serve                                    # MCP over stdio
```

Common commands:

| Command | Purpose |
|---|---|
| `countermap lookup "Cozy Bear"` | Any object by ID, name or alias |
| `countermap context T1539` | Full technique context |
| `countermap counter T1539 --tactic Detect` | D3FEND countermeasures with artifact paths |
| `countermap actor APT29 --with-software` | Actor techniques |
| `countermap gaps T1566.002 T1539 F1005.006` | Coverage gaps |
| `countermap coverage --log-source WinEventLog:Sysmon --platform Windows --actor APT29` | What your logs can detect, and where you are blind |
| `countermap rules-coverage --sigma ./rules --actor APT29 --layer out.json` | What your rules cover, gaps ranked by group use |
| `countermap render examples/aitm-bec-payment-fraud.json -o out/` | All four output formats |
| `countermap diff OLD.db NEW.db --kind technique` | What changed between snapshots |
| `countermap lock -o sources.lock.json` | Re-pin to the latest upstream releases |
| `countermap check-updates --lock sources.lock.json` | Exit code 10 when upstream has moved past the lock. Without `--lock` it reads `sources.lock.json` in the current directory, and when there is none it exits with code 2 and says how to get one |
| `countermap calibrate-cad exported.json` | Learn CAD handle IDs and schema version from a graph exported by CAD |

Environment variables:

| Variable | Effect |
|---|---|
| `COUNTERMAP_DB` | Database path (default `~/.cache/countermap/countermap.db`) |
| `COUNTERMAP_CACHE` | Download cache directory |
| `COUNTERMAP_URL_<KEY>` | Override one source with a URL or local path (for example `COUNTERMAP_URL_ATTACK_ENTERPRISE`) |
| `COUNTERMAP_CAD_CALIBRATION` | Path of the CAD calibration file |

### MCP clients

- **VS Code** reads `.vscode/mcp.json`. If VS Code cannot find `countermap`, point the command at the virtualenv executable using `${workspaceFolder}` rather than a machine-specific absolute path.
- **Claude Code, with the plugin:** `claude plugin install countermap --marketplace elchacal801/countermap`. The repository root holds `.claude-plugin/marketplace.json`, and `plugin/` holds the plugin itself:
  - `.claude-plugin/plugin.json`: the manifest.
  - `.mcp.json`: starts the server from PyPI with `uvx countermap@0.2.0 serve`.
  - `skills/countermap/`: tool guide and provenance rules.
  - `skills/threat-model/`: the `/countermap:threat-model` workflow.
- **Claude Code, without the plugin:** `claude mcp add --transport stdio countermap -- <path-to-venv>/bin/countermap serve`
- **Other clients:** any stdio MCP client can run `countermap serve`.

## Maintenance

### Tests and CI

`pytest -q` runs the offline suite against the small fixtures in `tests/conftest.py`, with no network access. `pytest -m live` runs the live test, which downloads real upstream data. The `ci` workflow runs the offline suite on Ubuntu with Python 3.10, 3.12 and 3.13 for every push to `main` and every pull request.

### Upstream updates

The `upstream-sync` workflow runs daily at 06:17 UTC (or by hand) and opens a pull request only when an upstream release version changes. The same check runs by hand with `countermap check-updates --lock sources.lock.json`. Before merging the workflow's pull request:

1. Read its body: which sources moved, the ATT&CK diff counts and the build warnings.
2. Look for new cross-framework warnings (links pointing at revoked, deprecated or missing objects). They usually mean an upstream project lags another, and they are candidates for upstream issues.
3. Merge only if CI is green.

The workflow declares the `contents: write` and `pull-requests: write` permissions it needs. For it to open pull requests, also enable "Allow GitHub Actions to create and approve pull requests" under Settings > Actions > General > Workflow permissions.

### New ATT&CK major release (April and October)

1. Rebuild locally.
2. Run `version_diff`, or `countermap diff` on the `.prev.db` snapshot.
3. Re-render the examples.
4. Check `countermap counter` on a few of the new techniques. Expect "predates this technique" notes until D3FEND catches up.

### A parser breaks

An upstream format change makes the build fail loudly for required sources and marks optional ones `failed`, recording the reason in `countermap info`. Fix the parser against the new format, add a fixture for it in `tests/conftest.py`, and never loosen a check just to make a build pass.

### D3FEND changes the CAD schema

Replace `src/countermap/emit/schemas/d3fend-cad-schema.json` from the schema page, export a fresh graph from CAD, and re-run `calibrate-cad`.

### Releasing

1. Set the version in `pyproject.toml` and `src/countermap/__init__.py`, and add a `CHANGELOG.md` entry.
2. Update the plugin. It starts the server from PyPI at a pinned version, so update `countermap@<version>` in `plugin/.mcp.json` and in both skills (including the threat-model skill's `allowed-tools`), bump `version` in `plugin/.claude-plugin/plugin.json`, and run `claude plugin validate . --strict`.
3. Build the sdist and wheel from a `git -c core.autocrlf=false archive` export of the tagged commit, never from a working tree, run `twine check --strict` on both, and list the sdist before uploading.
4. Rehearse on TestPyPI first, then upload to PyPI with a project-scoped token.
5. Push the release commit only once the new version is on PyPI, because the plugin starts the server from there.

Between releases, bump the plugin `version` whenever the skills change, because installed users stay on the version they have until it changes.

## Design decisions

| Decision | Reason |
|---|---|
| Python, SQLite + FTS5, no server process | Zero infrastructure; one file; fast enough (a build takes seconds after download, queries take milliseconds) |
| `mcp` 2.x, stdio transport only | Works with VS Code, Claude Code and other MCP clients without exposing a network port |
| Read-only server, no network at query time | Small attack surface; safe to give to agents |
| Store only MITRE-published links | Agents repeat what tools tell them; a stitched link presented as MITRE's is worse than no link |
| One scenario spec, four renderers | Agents never hand-write CAD JSON or STIX; every ID is checked before anything is drawn |
| D3FEND published inference, not a local reasoner | Matches what d3fend.mitre.org shows; avoids reimplementing its inference |
| Lock file + SHA-256 + scheduled PR | Reproducible builds; upstream changes are reviewed, not silently absorbed |
| Apache-2.0 | Matches ATLAS, F3 and Attack Flow; permissive; includes a patent grant |
| Package license `Apache-2.0 AND BSD-3-Clause` | The package ships 12 OASIS STIX schemas (BSD-3-Clause) for offline validation, and that license requires its text to travel with them |
| Claude Code plugin (skills plus the bundled stdio MCP server), not a standalone skill | A skill alone cannot start a local MCP server or download the data. The plugin bundles the server, and its skills carry the provenance rules and the threat-model workflow. |
