"""Render a resolved scenario as a Mermaid flowchart (renders in GitHub, VS Code, Confluence)."""

from __future__ import annotations

from ..scenario import ResolvedScenario


_ENTITIES = {"&": "#amp;", "<": "#lt;", ">": "#gt;", '"': "#quot;"}


def _q(text: str) -> str:
    """Escape user text for a quoted Mermaid label. Markup is added separately, never from user input."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(text))
    return "".join(_ENTITIES.get(ch, ch) for ch in text)


def render_mermaid(rs: ResolvedScenario, direction: str = "LR") -> str:
    lines = [f"flowchart {direction}", f"  %% {_q(rs.title)}"]
    ids = {s.id: f"s{i}" for i, s in enumerate(rs.steps, start=1)}
    for s in rs.steps:
        tactic = f"<br/><i>{_q(', '.join(t['name'] for t in s.tactics))}</i>" if s.tactics else ""
        gap = f"<br/>[{_q(rs.gap_label(s.id))}]" if rs.gap_label(s.id) else ""
        lines.append(f'  {ids[s.id]}["<b>{_q(s.technique_id)}</b><br/>{_q(s.label)}{tactic}{gap}"]:::step')
    for s in rs.steps:
        for prev in s.after:
            lines.append(f"  {ids[prev]} --> {ids[s.id]}")
    artifacts: dict[str, str] = {}
    counters: dict[tuple[str, str], str] = {}
    seen_edges: set[str] = set()

    def edge(line: str) -> None:
        if line not in seen_edges:
            seen_edges.add(line)
            lines.append(line)

    for link in rs.links:
        key = (link.d3fend_id, "official" if link.provenance == "official" else link.provenance)
        if key not in counters:
            counters[key] = f"c{len(counters) + 1}"
            tactic = f"<br/><i>{_q(link.tactic)}</i>" if link.tactic else ""
            tag = "" if link.provenance == "official" else f"<br/>[{_q(link.provenance)}]"
            style = "counter" if link.provenance == "official" else "derived"
            lines.append(f'  {counters[key]}{{{{"{_q(link.d3fend_id)}<br/>{_q(link.d3fend_name)}{tactic}{tag}"}}}}:::{style}')
        cm = counters[key]
        path = link.path or {}
        off, dfa = path.get("off_artifact"), path.get("def_artifact")
        for art in (off, dfa):
            if art and art not in artifacts:
                artifacts[art] = f"a{len(artifacts) + 1}"
                lines.append(f'  {artifacts[art]}[/"{_q(art)}"/]:::artifact')
        if off:
            label = _q(path.get("off_rel") or "acts on")
            if link.provenance == "official":
                edge(f'  {ids[link.step_id]} -- "{label}" --> {artifacts[off]}')
            else:
                edge(f'  {ids[link.step_id]} -. "{label} ({_q(link.provenance)})" .-> {artifacts[off]}')
        if dfa:
            edge(f'  {cm} -. "{_q(path.get("def_rel") or "acts on")}" .-> {artifacts[dfa]}')
        if off and dfa and off != dfa:
            edge(f"  {artifacts[off]} --- {artifacts[dfa]}")
        if not off and not dfa:
            edge(f'  {cm} -. "counters (analyst)" .-> {ids[link.step_id]}')
    lines += [
        "  classDef step fill:#fde8e8,stroke:#b42318,color:#1f1f1f",
        "  classDef artifact fill:#eef2f6,stroke:#475467,color:#1f1f1f",
        "  classDef counter fill:#e6f4ea,stroke:#137333,color:#1f1f1f",
        "  classDef derived fill:#fff4e5,stroke:#b54708,color:#1f1f1f,stroke-dasharray: 4 3",
    ]
    return "\n".join(lines) + "\n"
