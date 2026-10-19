# Changelog

Notable changes to Countermap, a local, read-only knowledge graph and MCP server for MITRE ATT&CK®, D3FEND, ATLAS and F3.

## 0.2.1 (2026-10-19)

### Fixed

- `coverage_gaps` no longer reports missing D3FEND data as missing D3FEND coverage. It recounted countermeasures from a list capped at 200 and ignored whether the D3FEND mappings were loaded, so without them every technique landed in `summary.no_official_d3fend` with a count of 0, and the "predates" distinction was lost. It now takes the official and derived totals from `countermeasures`, and when the D3FEND data is not loaded it gives null counts and lists the technique under `summary.d3fend_unavailable` instead.
- The build labeled the D3FEND ontology as required but completed without it. A required source (every source except `d3fend-mappings`) that cannot be fetched or ingested now fails the build, a Turtle or YAML syntax error included (which used to stop the build with a traceback), and a failed build leaves the existing database in place.

### Added

- `gap_reason`, which says why a countermeasure result is empty: `unavailable` (the D3FEND data is not loaded, which is not a gap), `predates`, `no_mapping`, `f3_native` or `none_in_tactic`, and null when there are countermeasures. `countermeasures` and `technique_context`'s `d3fend` block carry it, and each `coverage_gaps` entry carries it as `d3fend_gap_reason` with the notes as `d3fend_notes`; `summary.d3fend_predates` lists the `predates` techniques. The prose notes are unchanged.
- `steps_without_countermeasures` in `render_scenario` and `countermap render` results, with each step's `gap_reason`. The CAD step properties, Mermaid step labels and Navigator tooltips carry the same reason.
- `countermap build --allow-partial`, which builds without the required sources that cannot be fetched or ingested, records them as `unavailable` or `failed`, warns, and marks the database degraded. `countermap info` and the `datasets` tool report `degraded` and `missing_sources`.
- `SECURITY.md`, which explains how to report a vulnerability privately, and `CONTRIBUTING.md`.
- `examples/aitm-cookie-to-payment-change.json`, the scenario the README's diagram is rendered from.

### Changed

- A build fails by default when a required source is missing; pass `--allow-partial` to build without it. Without the D3FEND ontology, the mappings are now recorded as unavailable instead of being left out of `countermap info`.
- The README now leads with what is distinctive, a quick start and a rendered diagram, and covers the Claude Code versions the plugin commands need and how to update the plugin. It also documents that a lock pins each source's primary URL with no fallback, and how to build from a mirror on a network that blocks an upstream host.
- The MCP server instructions, the tool descriptions and both plugin skills tell agents to read `gap_reason` and `summary.d3fend_unavailable`, and the `countermap` skill says what to do when the first build fails behind a proxy.
- The plugin starts the server with `uvx countermap@0.2.1`.

### Upgrading

Auto-update is off by default for third-party Claude Code marketplaces. To update the plugin:

```bash
claude plugin marketplace update countermap
claude plugin update countermap@countermap
```

The new version loads in the next session, or after `/reload-plugins`. On the command line, upgrade with `pip install -U countermap` or `pipx upgrade countermap`. Databases built by 0.2.0 keep working without a rebuild.

## 0.2.0 (2026-10-19)

The first public release.

### Added

- A local SQLite knowledge graph of ATT&CK (Enterprise, Mobile, ICS), D3FEND, ATLAS and F3, served read-only to AI agents over MCP (14 tools) and to people through the `countermap` CLI: search, lookup by ID, name or alias, technique context, D3FEND countermeasures with artifact paths, ATLAS and F3 crosswalks to ATT&CK, actor techniques and comparison, coverage gaps and Navigator layers.
- Provenance on every cross-framework link: `official` when MITRE published it, `derived` when Countermap composed it at query time (with the `via` path it took), and `analyst` when a scenario asserts it. An empty D3FEND result says whether D3FEND has no mapping for the technique or predates it.
- Upstream data checks: links that point at revoked, deprecated or missing objects are reported as build warnings and flagged in results.
- Reproducible builds: a lock file pins each upstream release by URL and SHA-256 (`countermap lock`, `countermap build --lock`), any source can come from a mirror or a local file, and `countermap check-updates` reports when an upstream release has moved past the lock. A scheduled `upstream-sync` GitHub Actions workflow runs that check and opens a pull request with the new lock.
- `render_scenario` (MCP) and `countermap render` (CLI): one scenario spec, checked against the loaded data, renders a D3FEND CAD graph, an Attack Flow 2.0 bundle, ATT&CK Navigator layers (including F3's Navigator domain) and a Mermaid diagram. The CAD graph and the Attack Flow bundle are validated against their published schemas. Results list the ATT&CK mitigations (`step_mitigations`) and detection strategies (`step_detections`) MITRE links to each step, and the Navigator tooltips carry them too.
- ATT&CK's detection model: detection strategies, analytics with their log sources and tunables, and data components, through `lookup` and `technique_context`. Campaigns carry their first and last seen dates.
- `telemetry_coverage` (MCP) and `countermap coverage` (CLI): given the log sources and data components you collect, each technique of a list, an actor or a platform is classified as covered, partial, blind, no analytic for the platform, or no detection strategy, against MITRE's analytics, with an optional Navigator layer.
- `rule_coverage` (MCP) and `countermap rules-coverage` (CLI): given the ATT&CK IDs a ruleset maps to, each in-scope technique is classified as covered, partial or uncovered, and the gaps are ranked by how many groups ATT&CK links to them. The CLI can read the IDs from the tags of a folder of Sigma rules.
- `version_diff` (MCP) and `countermap diff` (CLI): objects added, removed, revoked, deprecated, renamed or moved between tactics since the previous build.
- A Claude Code plugin with two skills: `countermap` teaches the tools and the provenance rules, and `/countermap:threat-model` turns an incident or report into a mapped scenario with mitigations, detections, countermeasures, gaps and diagram files. It starts the server from PyPI with `uvx countermap@0.2.0`.
- `docs/ARCHITECTURE.md`: the design, the provenance and coverage rules, the upstream sources and the maintenance runbook.

### Notes

- Built and tested against ATT&CK 20.0, F3 1.2, ATLAS 2026.09 and D3FEND 1.6.0, as pinned in `sources.lock.json`.
- Requires Python 3.10 or newer, and installs with pip, pipx or uvx.
- The package license is `Apache-2.0 AND BSD-3-Clause`, because the package ships 12 OASIS STIX 2.1 schemas for offline validation. `NOTICE` lists MITRE's attributions and trademarks.
