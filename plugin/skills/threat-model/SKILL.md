---
name: threat-model
description: Turns an incident write-up, attack narrative or threat report into a cross-framework threat model using the Countermap MCP tools. Maps each step to MITRE ATT&CK®, ATLAS or F3 techniques, lists the MITRE mitigations and detection strategies for each step, picks D3FEND countermeasures with provenance, reports coverage gaps, and writes D3FEND CAD, Attack Flow 2.0, ATT&CK Navigator and Mermaid files. Use it when the user asks to threat-model something, map an incident, intrusion or report to ATT&CK, build an attack flow or attack graph, find defenses for an attack chain, or produce D3FEND CAD or Navigator output.
argument-hint: "<incident narrative, report file or URL>"
allowed-tools: Bash(uvx countermap@0.2.2 render:*), Bash(countermap render:*), PowerShell(uvx countermap@0.2.2 render:*), PowerShell(countermap render:*)
---

# Threat model with Countermap

Produce a threat model the user can defend in front of a reviewer: each step traceable to the source material, each technique a real ID in the loaded data, and each countermeasure labeled as MITRE-published or not. The `countermap` skill explains the tools and provenance rules; follow it too. If the tools say the database is missing, do its one-time build step first.

## 1. Read the source and extract the steps

Take the input from the arguments: pasted text, a file path, or a URL. List what the adversary did, in order. Keep each step to one behavior ("sent a link to an AiTM login page", "replayed the stolen session cookie"), and note which steps ran in parallel.

Keep evidence and inference apart. If the source says the actor "likely" did something, or you are filling a gap, mark the step as hypothesized in its description. The diagram looks equally confident either way, so the description is the only place that difference survives.

## 2. Map each step to a technique

- **Find candidates by keyword** with `search`, then confirm the best one with `lookup` or `technique_context`. Read the description and check it matches what happened, not just the keyword.
- **Prefer sub-techniques** when the source supports them (T1566.002 rather than T1566). Use the parent when it doesn't.
- **Use the right framework:** ATT&CK for intrusion behavior, F3 (`F` IDs, or `f3:` for reused IDs) for fraud and monetization, ATLAS (`AML.` IDs) for attacks on AI systems. One scenario can mix them.
- **Don't force a fit.** If nothing matches, say so; Countermap rejects unknown IDs, and the gap is itself a finding.

These mappings are your judgment, not MITRE's. Say so in the report.

## 3. Write the scenario spec

```json
{
  "title": "AiTM phishing to payment redirection",
  "description": "One-paragraph summary, with the source it came from",
  "authors": ["<the user's name, if known>"],
  "steps": [
    {"id": "s1", "technique": "T1566.002", "description": "Link to an AiTM reverse-proxy login page"},
    {"id": "s2", "technique": "T1539", "after": ["s1"], "assets": ["Victim mailbox"]},
    {"id": "s3", "technique": "F1005.006", "after": ["s2"], "description": "Hypothesized: vendor bank details changed"}
  ],
  "countermeasures": "auto",
  "max_countermeasures_per_step": 2
}
```

Each step takes these fields:

- **`id`:** letters, digits, `.`, `_` or `-`, up to 40 characters.
- **`technique`:** the technique ID.
- **`name`** (optional): a label for the step; it defaults to the technique name.
- **`description`:** what happened in this step.
- **`after`:** the IDs of the steps that precede this one. The graph must not contain a cycle.
- **`assets`:** what the step touched, as free text.

`countermeasures` can be:

- **`"auto"`:** picks official D3FEND countermeasures per step, spread across tactics, preferring ones that act on the same artifact. This is usually right.
- **`"none"`:** no countermeasures are drawn.
- **A list such as `[{"id": "D3-MFA", "targets": ["s2"]}]`:** names countermeasures explicitly. D3FEND links that it doesn't publish are drawn and labeled as analyst assertions.

`d3fend_tactics` (for example `["Harden", "Detect"]`) restricts the automatic picks to those tactics.

## 4. Render, check gaps and save the files

1. Call `render_scenario` with the spec and `formats: ["mermaid"]`. Set `scope` to `incident`, `campaign`, `threat-actor` or another listed value to match the source.
   - The result carries the validation, warnings, `countermeasure_links`, `steps_without_countermeasures` (with each step's `gap_reason`), `step_mitigations` and `step_detections` you need for the report.
   - Asking only for Mermaid keeps the large CAD and Attack Flow JSON out of the conversation.
   - If it returns an error (an unknown ID, an unknown predecessor or a cycle), fix the spec and render again.
2. If `"auto"` picked countermeasures that don't fit a step, replace them with an explicit list and render again. Say so in the report.
3. Call `coverage_gaps` with the technique IDs.
   - If the user has said which logs they collect, also call `telemetry_coverage` with the scenario's ATT&CK technique IDs as `techniques`, their log sources (and data components, if they named any) and their main platform. Don't guess their telemetry; if they haven't said, offer this check at the end instead.
4. Choose a short slug from the title and write the spec to `countermap-out/<slug>.scenario.json`.
5. Let the CLI write every diagram file, rather than copying JSON by hand. Hand copies are slow and a single typo breaks a file.
   ```bash
   uvx countermap@0.2.2 render countermap-out/<slug>.scenario.json -o countermap-out --name <slug> --scope <scope>
   ```
   Run it on its own, exactly as written, not chained with other commands or wrapped in a check for the CLI. The skill pre-approves this one command, and that only applies when it runs by itself. Use `countermap render ...` instead if the CLI is installed. It writes:
   - `<slug>.d3fend-cad.json`
   - `<slug>.attack-flow.json`
   - `<slug>.mmd`
   - `<slug>.navigator.<domain>.json`, one file per domain
6. If the command can't run, call `render_scenario` for the remaining formats and write those files yourself. In that case, tell the user the files were transcribed by hand and should be checked.

## 5. Report

Use this structure:

1. **Summary:** two or three sentences on the attack chain and where defenses are thinnest.
2. **Steps:** a table with the step, technique (ID, name, framework), evidence or hypothesis, and the source excerpt it came from.
3. **ATT&CK mitigations:** from `step_mitigations`, a table with the step, its technique, and each mitigation MITRE links to it (ID and name; ATLAS mitigations for `AML.` steps). These are MITRE's own links, so they are official; they are the organization-level controls (MFA, user training, application control) a reader can act on directly.
   - Group repeated mitigations, so one that covers several steps is listed once, with those steps.
   - Mark steps with none. For F3 steps, say that F3 has not published mitigations, rather than leaving a blank.
4. **Detection:** from `step_detections`, for each step, the ATT&CK detection strategy (ID and name) and the log sources to hunt in.
   - Group each strategy's log sources by platform: log source, channel, then data component, for example "Windows: `WinEventLog:Sysmon` EventCode=10 (DC0035 Process Access)".
   - Only list platforms that fit the source material, and say which ones you left out.
   - For the steps that matter most, you may quote a short analytic description from the strategy's `analytics` and name its tunables (the fields MITRE marks for tuning, such as allowlists and time windows), so the reader knows what to adapt.
   - These are MITRE's own detection strategies.
   - Mark steps with none. F3 has not published data sources.
   - If you ran `telemetry_coverage`, say which steps are blind to the user's telemetry, which are partial and what each is missing, and which are covered. Say that this classification is Countermap's computation over MITRE's analytics, not MITRE's, and that covered means the logs exist, not that a rule does.
5. **D3FEND countermeasures:** a table with the D3FEND ID and name, tactic, provenance (official, derived with its `via`, or analyst), the steps it covers, and the artifact path. For each step in `steps_without_countermeasures`, give its reason instead of leaving a blank.
6. **Gaps:** techniques with no mitigation, no detection strategy or no D3FEND mapping, and steps blind to the user's telemetry if you checked it. Use each step's `gap_reason` (and `coverage_gaps`' `d3fend_gap_reason`): distinguish "D3FEND has no mapping" (`no_mapping`) from "the loaded D3FEND release predates this technique" (`predates`) and from F3-native techniques (`f3_native`).
   - `unavailable` (or an ID in `coverage_gaps`' `summary.d3fend_unavailable`) is not a gap: say the D3FEND countermeasures could not be checked because the D3FEND data is not loaded, and suggest rebuilding the database.
7. **Warnings:** anything `render_scenario` or `coverage_gaps` flagged (revoked IDs, ambiguous names, omitted countermeasures).
8. **Files:** where each was written and how to open it:
   - CAD: https://d3fend.mitre.org/cad/, then File > Load.
   - Navigator: https://mitre-attack.github.io/attack-navigator/, then Open Existing Layer > Upload from local. Each technique's tooltip lists its mitigations and detection strategy.
   - Attack Flow: CTID's Attack Flow Builder.
   - Mermaid: renders in GitHub and VS Code.

End by stating the dataset versions (from `datasets` or the render output), and that the step-to-technique mapping is your analysis while MITRE publishes the mitigation links, the detection strategies and the D3FEND links marked official.
