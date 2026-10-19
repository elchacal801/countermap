# Security policy

## Supported versions

Security fixes go into the latest 0.2.x release. Earlier releases are not patched, so upgrade to the latest release before reporting if you can.

| Version | Supported |
|---|---|
| 0.2.x (latest) | Yes |
| Earlier | No |

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, pull request or discussion for a suspected vulnerability.

Please include:

- the Countermap version (`countermap --version`), the Python version and the operating system;
- how Countermap was run: a CLI command, an MCP client, or the Claude Code plugin;
- steps to reproduce, with a minimal input where possible (a scenario spec, a Sigma file, a lock file or a tool call);
- what an attacker could do with it, as you understand it.

## What to expect

There are no fixed response times. Reports are read and acknowledged as soon as possible, and the reporter is kept informed until the issue is fixed or declined, with the reason. A fix ships as a new 0.2.x release with a GitHub security advisory that credits the reporter, unless they prefer otherwise. Please keep the details private until the fix is released.

## Scope

Countermap's design limits what an attacker can reach, and reports that break these properties are in scope:

- **Read-only server.** The MCP server opens the database read-only, and its tools cannot write files, run commands or reach the network. Tools take IDs and scenario specs, never file paths.
- **No network at query time.** Only `build`, `lock` and `check-updates` touch the network, and only the upstream URLs or the overrides you pass.
- **Verified builds.** Builds fetch upstream data over HTTPS. Under a lock file, each source is checked against its pinned SHA-256 and a mismatch fails the build. A source overridden with `--source` is not checked.
- **Sigma parsing is CLI-only.** `countermap rules-coverage --sigma` parses YAML with `yaml.safe_load_all` and never runs anything in it. It does not follow symlinks or junctions, skips files over 1 MiB or nested more than 100 brackets deep, and counts files it cannot parse instead of stopping.
- **Rendered output.** User text in scenario specs is escaped in the Mermaid output, and the CAD and Attack Flow output is validated against their schemas before it is returned.

Also in scope: a crash or hang caused by crafted input (a scenario spec, a Sigma file, a lock file or upstream data), and code execution from any of them.

Out of scope:

- Errors or disputed content in the MITRE ATT&CK®, D3FEND, ATLAS or F3 data. Report those to the upstream project; Countermap reports the data problems it detects as build warnings.
- Vulnerabilities in dependencies, which belong with their maintainers. A note on how one affects Countermap is still welcome.
- Tool results that contain upstream text. Results include MITRE's descriptions, which agents should treat as data, not instructions; a way to make Countermap itself act on such text is in scope.
- The security of the machine or the MCP client that runs Countermap.
