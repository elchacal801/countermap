# Contributing to Countermap

Bug reports, fixes and improvements are welcome. For anything larger than a small fix, open an issue first so the approach can be agreed before the work starts. To report a vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Development setup

Python 3.10 or newer.

```bash
git clone https://github.com/elchacal801/countermap && cd countermap
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes the modules, the data flow and the maintenance runbook.

## Tests

- `pytest -q` runs the offline suite against small hand-built fixtures in `tests/conftest.py` that mirror the real upstream formats. It never touches the network.
- `pytest -m live` runs the live test, which downloads real upstream data (about 150 MB). It is deselected by default; run it when a change touches the build or a parser.

Every change comes with tests in the offline suite: write the failing test first, then the fix. Never loosen an existing check to make a test or a build pass. When an upstream format changes, fix the parser and add a fixture for the new format to `tests/conftest.py`.

## Provenance rules

These rules are the point of the project, and a change that weakens one is not accepted. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has the full list.

1. **Only MITRE-published links are stored.** MITRE ATT&CK® relationships, ATLAS's ATT&CK references, F3's reuse of ATT&CK IDs and D3FEND's published inference output. Countermap does not compute its own countermeasure links.
2. **Derived links are labeled.** Anything composed at query time is `derived` and carries the `via` path it was composed through; it is never presented as MITRE's.
3. **Gaps are reported as gaps.** An empty result says why it is empty (`gap_reason`), a gap is never filled with a guess, and data that is not loaded is reported as unavailable, never as empty.
4. **Computed results say so.** Coverage classes and rankings are Countermap's arithmetic over MITRE's data, and each carries a `basis` that says so.

## Upstream data problems

The build reports problems it finds in upstream releases, such as links to revoked, deprecated or missing objects, as warnings; it does not correct the data. Report those to the upstream project:

- ATT&CK: `mitre-attack/attack-stix-data`
- D3FEND: `d3fend/d3fend-ontology`
- ATLAS: `mitre-atlas/atlas-data`
- F3: `center-for-threat-informed-defense/fight-fraud-framework`

Open an issue here when Countermap handles the data wrongly.

## Documentation style

- ASCII only, apart from the registered-mark sign in "MITRE ATT&CK®". No em or en dashes.
- US English, and no first person in repository documents.
- MITRE's trademark wording: "MITRE ATT&CK®" at the first reference in a document, "ATT&CK" after that. ATT&CK never appears in a product or project name.
- When behavior changes, update the README and `docs/ARCHITECTURE.md` together.

## The Claude Code plugin

`plugin/` holds the plugin: its manifest, the MCP server entry (which starts the server from PyPI at a pinned version) and two skills. Whenever a skill changes, bump `version` in `plugin/.claude-plugin/plugin.json`, because installed users stay on the version they have until it changes, and run `claude plugin validate . --strict`.

## Pull requests

- Keep each pull request small and focused on one change, with its tests.
- Say what changed and why, and link the issue it addresses.
- Describe user-visible changes so they can go into `CHANGELOG.md`.
- The offline suite must pass on Python 3.10 and newer.

Contributions are accepted under the project's license, Apache-2.0.
