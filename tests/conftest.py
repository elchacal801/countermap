"""Small, hand-built upstream fixtures that mirror the real formats (ATT&CK STIX 2.1,
F3 STIX, ATLAS v6 YAML, D3FEND TTL, D3FEND SPARQL-JSON mappings). Tests never touch the network."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
import yaml

from countermap.ingest import build
from countermap.query import Countermap
from countermap.sources import ResolvedSource

NS = uuid.UUID("0b0c0d0e-0000-4000-8000-000000000001")


def sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, kind + key)}"


def ext(ext_id: str, source: str = "mitre-attack", url: str | None = None) -> list[dict]:
    return [{"source_name": source, "external_id": ext_id, "url": url or f"https://example.test/{ext_id}"}]


def tactic(ext_id, name, short, chain="mitre-attack"):
    return {"type": "x-mitre-tactic", "id": sid("x-mitre-tactic", chain + ext_id), "name": name,
            "x_mitre_shortname": short, "external_references": ext(ext_id, chain if chain == "mitre-f3" else "mitre-attack")}


def technique(ext_id, name, phases, *, chain="mitre-attack", sub=False, revoked=False, deprecated=False, platforms=("Windows",)):
    return {"type": "attack-pattern", "id": sid("attack-pattern", chain + ext_id), "name": name,
            "description": f"{name} description.", "kill_chain_phases": [{"kill_chain_name": chain, "phase_name": p} for p in phases],
            "external_references": ext(ext_id, chain if chain == "mitre-f3" else "mitre-attack"),
            "x_mitre_is_subtechnique": sub, "revoked": revoked, "x_mitre_deprecated": deprecated,
            "x_mitre_platforms": list(platforms), "x_mitre_domains": ["enterprise-attack"]}


def rel(src, rtype, dst, **extra):
    return {"type": "relationship", "id": sid("relationship", src + rtype + dst), "source_ref": src,
            "relationship_type": rtype, "target_ref": dst, **extra}


def attack_bundle(version="20.0", extra_objects=(), drop=(), rename=None):
    t = {
        "ia": tactic("TA0001", "Initial Access", "initial-access"),
        "ca": tactic("TA0006", "Credential Access", "credential-access"),
        "st": tactic("TA0005", "Stealth", "stealth"),
    }
    techs = {
        "T1566": technique("T1566", "Phishing", ["initial-access"]),
        "T1566.002": technique("T1566.002", "Spearphishing Link", ["initial-access"], sub=True),
        "T1539": technique("T1539", "Steal Web Session Cookie", ["credential-access"]),
        "T1656": technique("T1656", "Impersonation", ["stealth"], revoked=True),
        "T1684": technique("T1684", "Social Engineering", ["stealth"]),
        "T1684.001": technique("T1684.001", "Impersonation", ["stealth"], sub=True),
    }
    if rename:
        for k, v in rename.items():
            techs[k]["name"] = v
    for d in drop:
        techs.pop(d, None)
    legacy = {"type": "course-of-action", "id": sid("course-of-action", "legacy-T1539"),
              "name": "Steal Web Session Cookie Mitigation", "x_mitre_deprecated": True, "external_references": ext("T1539")}
    m1017 = {"type": "course-of-action", "id": sid("course-of-action", "M1017"), "name": "User Training", "external_references": ext("M1017")}
    apt29 = {"type": "intrusion-set", "id": sid("intrusion-set", "G0016"), "name": "APT29",
             "aliases": ["APT29", "Cozy Bear"], "external_references": ext("G0016")}
    apt28 = {"type": "intrusion-set", "id": sid("intrusion-set", "G0007"), "name": "APT28",
             "aliases": ["APT28", "Fancy Bear"], "external_references": ext("G0007")}
    tool = {"type": "tool", "id": sid("tool", "S0001"), "name": "CookieGrabber", "external_references": ext("S0001")}
    camp = {"type": "campaign", "id": sid("campaign", "C0001"), "name": "Operation Test", "external_references": ext("C0001"),
            "first_seen": "2023-02-01T05:00:00.000Z", "last_seen": "2024-06-01T04:00:00.000Z",
            "x_mitre_first_seen_citation": "(Citation: Test Report 2023)",
            "x_mitre_last_seen_citation": "(Citation: Test Follow-up 2024)"}
    dc = {"type": "x-mitre-data-component", "id": sid("x-mitre-data-component", "DC0001"), "name": "Web Credential Usage",
          "external_references": ext("DC0001")}
    an = {"type": "x-mitre-analytic", "id": sid("x-mitre-analytic", "AN0001"), "name": "Analytic 0001",
          "x_mitre_platforms": ["Identity Provider"], "external_references": ext("AN0001"),
          "x_mitre_log_source_references": [{"x_mitre_data_component_ref": dc["id"], "name": "IdP:SignIn", "channel": "token replay"}]}
    det = {"type": "x-mitre-detection-strategy", "id": sid("x-mitre-detection-strategy", "DET0001"),
           "name": "Detect cookie replay", "x_mitre_analytic_refs": [an["id"]], "external_references": ext("DET0001")}
    matrix = {"type": "x-mitre-matrix", "id": sid("x-mitre-matrix", "ent"), "name": "Enterprise ATT&CK",
              "tactic_refs": [t["ia"]["id"], t["ca"]["id"], t["st"]["id"]], "external_references": ext("enterprise-attack")}
    rels = [
        rel(techs["T1566.002"]["id"], "subtechnique-of", techs["T1566"]["id"]),
        rel(techs["T1684.001"]["id"], "subtechnique-of", techs["T1684"]["id"]),
        rel(m1017["id"], "mitigates", techs["T1566.002"]["id"]),
        rel(apt29["id"], "uses", techs["T1566.002"]["id"]),
        rel(apt29["id"], "uses", tool["id"]),
        rel(apt28["id"], "uses", techs["T1566.002"]["id"]),
        rel(apt28["id"], "uses", techs["T1684.001"]["id"]),
        rel(tool["id"], "uses", techs["T1539"]["id"]),
        rel(camp["id"], "attributed-to", apt29["id"]),
        rel(camp["id"], "uses", techs["T1539"]["id"]),
        rel(det["id"], "detects", techs["T1539"]["id"]),
        rel(apt29["id"], "uses", techs["T1684"]["id"], x_mitre_deprecated=True),  # must be skipped
    ]
    if "T1656" in techs:
        rels.append(rel(techs["T1656"]["id"], "revoked-by", techs["T1684.001"]["id"]))
    rels = [r for r in rels if all(ref in {o["id"] for o in [*techs.values(), m1017, apt29, apt28, tool, camp, det]}
                                   for ref in (r["source_ref"], r["target_ref"]))]
    objects = [
        {"type": "x-mitre-collection", "id": sid("x-mitre-collection", "ent"), "x_mitre_version": version, "name": "Enterprise ATT&CK"},
        matrix, *t.values(), *techs.values(), legacy, m1017, apt29, apt28, tool, camp, dc, an, det, *rels, *extra_objects,
    ]
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid5(NS, "ent" + version)), "objects": objects}


LONG_ANALYTIC_DESCRIPTION = (
    "Detects PowerShell launched with encoded or obfuscated command lines by a parent process that does not "
    "normally start a shell. Correlate the process creation event with script block logging for the same "
    "process, and flag script blocks that download content, reflectively load assemblies or disable "
    "security tooling. Expect noise from software deployment agents and administrative automation."
)


def detection_objects() -> list[dict]:
    """Extra Enterprise objects for the detection-model and coverage tests, added to ``attack_bundle``.

    Analytics mix log sources and channels (Sysmon, Security with an EventCode list, a channel of "None",
    a log source name with a space, one analytic with no log sources at all) across Windows, Linux and IaaS.
    Two groups use techniques directly and through software, and a campaign breaks ranking ties.
    """
    tac = [tactic("TA0002", "Execution", "execution"), tactic("TA0007", "Discovery", "discovery"),
           tactic("TA0011", "Command and Control", "command-and-control")]
    t = {
        "T1059": technique("T1059", "Command and Scripting Interpreter", ["execution"], platforms=("Windows", "Linux")),
        "T1059.001": technique("T1059.001", "PowerShell", ["execution"], sub=True),
        "T1059.004": technique("T1059.004", "Unix Shell", ["execution"], sub=True, platforms=("Linux",)),
        "T1003": technique("T1003", "OS Credential Dumping", ["credential-access"], platforms=("Windows", "Linux")),
        "T1003.001": technique("T1003.001", "LSASS Memory", ["credential-access"], sub=True),
        "T1105": technique("T1105", "Ingress Tool Transfer", ["command-and-control"], platforms=("Windows", "Linux")),
        "T1070": technique("T1070", "Indicator Removal", ["stealth"]),
        "T1538": technique("T1538", "Cloud Service Dashboard", ["discovery"], platforms=("IaaS",)),
        "T1027": technique("T1027", "Obfuscated Files or Information", ["stealth"]),
    }

    def data_component(ext_id, name):
        return {"type": "x-mitre-data-component", "id": sid("x-mitre-data-component", ext_id), "name": name,
                "description": f"{name}.", "external_references": ext(ext_id)}

    dc = {
        "DC0032": data_component("DC0032", "Process Creation"),
        "DC0035": data_component("DC0035", "Process Access"),
        "DC0029": data_component("DC0029", "Script Execution"),
        "DC0082": data_component("DC0082", "Network Connection Creation"),
        "DC0067": data_component("DC0067", "Logon Session Creation"),
    }

    def analytic(ext_id, platform, refs, mutable=(), description=None):
        obj = {"type": "x-mitre-analytic", "id": sid("x-mitre-analytic", ext_id), "name": f"Analytic {ext_id[2:]}",
               "description": description or f"{ext_id} detection logic.", "x_mitre_platforms": [platform],
               "external_references": ext(ext_id),
               "x_mitre_log_source_references": [{"x_mitre_data_component_ref": dc[d]["id"], "name": n, "channel": ch}
                                                 for d, n, ch in refs]}
        if mutable:
            obj["x_mitre_mutable_elements"] = [{"field": f, "description": d} for f, d in mutable]
        return obj

    an = {
        "AN0100": analytic("AN0100", "Windows", [("DC0032", "WinEventLog:Sysmon", "EventCode=1"),
                                                 ("DC0029", "WinEventLog:PowerShell", "EventCode=4104")],
                           mutable=[("ScriptBlockAllowList", "Signed administrative scripts to ignore.")],
                           description=LONG_ANALYTIC_DESCRIPTION),
        "AN0101": analytic("AN0101", "Windows", [("DC0032", "WinEventLog:Sysmon", "EventCode=1")],
                           mutable=[("ParentProcessAllowList", "Parents allowed to start PowerShell."),
                                    ("TimeWindow", "Correlation window in seconds.")]),
        "AN0102": analytic("AN0102", "Windows", [("DC0035", "WinEventLog:Sysmon", "EventCode=10"),
                                                 ("DC0035", "WinEventLog:Security", "EventCode=4663, 4656")],
                           mutable=[("GrantedAccessMask", "Access masks treated as credential reads.")]),
        "AN0104": analytic("AN0104", "Windows", [("DC0082", "Network Traffic", "None")]),
        "AN0105": analytic("AN0105", "Linux", [("DC0082", "auditd:SYSCALL", "connect")]),
        "AN0106": analytic("AN0106", "IaaS", [("DC0067", "AWS:CloudTrail", "ConsoleLogin")]),
        "AN0107": analytic("AN0107", "Windows", []),
        "AN0108": analytic("AN0108", "Linux", [("DC0032", "auditd:SYSCALL", "execve")]),
    }

    def strategy(ext_id, name, analytics):
        return {"type": "x-mitre-detection-strategy", "id": sid("x-mitre-detection-strategy", ext_id), "name": name,
                "x_mitre_analytic_refs": [an[a]["id"] for a in analytics], "external_references": ext(ext_id)}

    det = {
        "DET0100": strategy("DET0100", "Detect suspicious PowerShell", ["AN0100", "AN0101"]),
        "DET0101": strategy("DET0101", "Detect LSASS access", ["AN0102"]),
        "DET0102": strategy("DET0102", "Detect tool downloads", ["AN0104", "AN0105"]),
        "DET0103": strategy("DET0103", "Detect cloud dashboard use", ["AN0106"]),
        "DET0104": strategy("DET0104", "Detect obfuscated files", ["AN0107"]),
        "DET0105": strategy("DET0105", "Detect Unix shell abuse", ["AN0108"]),
    }
    sandcastle = {"type": "intrusion-set", "id": sid("intrusion-set", "G0100"), "name": "Sandcastle",
                  "aliases": ["Sandcastle"], "external_references": ext("G0100")}
    driftwood = {"type": "intrusion-set", "id": sid("intrusion-set", "G0101"), "name": "Driftwood",
                 "aliases": ["Driftwood"], "external_references": ext("G0101")}
    pulley = {"type": "tool", "id": sid("tool", "S0100"), "name": "Pulley", "external_references": ext("S0100")}
    tidepool = {"type": "campaign", "id": sid("campaign", "C0100"), "name": "Operation Tidepool",
                "external_references": ext("C0100")}
    rels = [
        rel(t["T1059.001"]["id"], "subtechnique-of", t["T1059"]["id"]),
        rel(t["T1059.004"]["id"], "subtechnique-of", t["T1059"]["id"]),
        rel(t["T1003.001"]["id"], "subtechnique-of", t["T1003"]["id"]),
        rel(det["DET0100"]["id"], "detects", t["T1059.001"]["id"]),
        rel(det["DET0101"]["id"], "detects", t["T1003.001"]["id"]),
        rel(det["DET0102"]["id"], "detects", t["T1105"]["id"]),
        rel(det["DET0103"]["id"], "detects", t["T1538"]["id"]),
        rel(det["DET0104"]["id"], "detects", t["T1027"]["id"]),
        rel(det["DET0105"]["id"], "detects", t["T1059.004"]["id"]),
        *[rel(sandcastle["id"], "uses", t[x]["id"]) for x in ("T1059.001", "T1003.001", "T1105", "T1070", "T1538", "T1027")],
        *[rel(driftwood["id"], "uses", t[x]["id"]) for x in ("T1105", "T1003.001")],
        rel(driftwood["id"], "uses", pulley["id"]),
        *[rel(pulley["id"], "uses", t[x]["id"]) for x in ("T1105", "T1070", "T1059.004")],
        rel(tidepool["id"], "uses", t["T1105"]["id"]),
    ]
    return [*tac, *t.values(), *dc.values(), *an.values(), *det.values(), sandcastle, driftwood, pulley, tidepool, *rels]


def ics_bundle(extra_objects=()):
    dup = {"type": "malware", "id": sid("malware", "ics-dup"), "name": "LegacyThing", "x_mitre_deprecated": True,
           "external_references": ext("S0001"), "x_mitre_domains": ["ics-attack"]}
    tac = tactic("TA0108", "Initial Access", "initial-access-ics")
    tech = technique("T0001", "Exploit Workstation", ["initial-access-ics"], chain="mitre-ics-attack")
    tech["external_references"] = ext("T0001")
    tech["x_mitre_domains"] = ["ics-attack"]
    asset = {"type": "x-mitre-asset", "id": sid("x-mitre-asset", "A0001"), "name": "Workstation",
             "external_references": ext("A0001"), "x_mitre_domains": ["ics-attack"]}
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid5(NS, "ics")), "objects": [
        {"type": "x-mitre-collection", "id": sid("x-mitre-collection", "ics"), "x_mitre_version": "20.0", "name": "ICS ATT&CK"},
        dup, tac, tech, asset, rel(tech["id"], "targets", asset["id"]), *extra_objects]}


UNRESOLVABLE_DC_REF = "x-mitre-data-component--00000000-0000-4000-8000-0000000000aa"


def ics_detection_objects() -> list[dict]:
    """ICS analytics whose log-source references point outside the ICS bundle, as 8 do in ATT&CK 20.0.

    AN0200 references DC0001, which only the Enterprise fixture bundle publishes; AN0201 references a data
    component no bundle publishes.
    """
    t0001 = sid("attack-pattern", "mitre-ics-attackT0001")

    def analytic(ext_id, refs):
        return {"type": "x-mitre-analytic", "id": sid("x-mitre-analytic", ext_id), "name": f"Analytic {ext_id[2:]}",
                "description": f"{ext_id} detection logic.", "x_mitre_platforms": ["Windows"],
                "x_mitre_domains": ["ics-attack"], "external_references": ext(ext_id),
                "x_mitre_log_source_references": [{"x_mitre_data_component_ref": d, "name": n, "channel": ch}
                                                  for d, n, ch in refs]}

    an200 = analytic("AN0200", [(sid("x-mitre-data-component", "DC0001"), "IdP:SignIn", "workstation logon")])
    an201 = analytic("AN0201", [(UNRESOLVABLE_DC_REF, "historian:applog", "None")])
    det = {"type": "x-mitre-detection-strategy", "id": sid("x-mitre-detection-strategy", "DET0200"),
           "name": "Detect workstation exploitation", "x_mitre_analytic_refs": [an200["id"], an201["id"]],
           "x_mitre_domains": ["ics-attack"], "external_references": ext("DET0200")}
    return [an200, an201, det, rel(det["id"], "detects", t0001)]


def f3_bundle():
    chain = "mitre-f3"
    ia = tactic("TA0001", "Initial Access", "initial-access", chain)
    mon = tactic("FA0002", "Monetization", "monetization", chain)
    techs = [
        technique("T1566", "Phishing", ["initial-access"], chain=chain),
        technique("F1005", "Account Manipulation", ["monetization"], chain=chain),
        technique("F1005.006", "Account Manipulation: Change of Payment Details", ["monetization"], chain=chain, sub=True),
        technique("T1656", "Impersonation", ["initial-access"], chain=chain),
        technique("T1586.004", "Compromise Accounts: Corporate Accounts", ["initial-access"], chain=chain, sub=True),
    ]
    by = {t["external_references"][0]["external_id"]: t for t in techs}
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid5(NS, "f3")), "objects": [
        {"type": "x-mitre-collection", "id": sid("x-mitre-collection", "f3"), "name": "F3", "x_mitre_version": "1.2"},
        {"type": "x-mitre-matrix", "id": sid("x-mitre-matrix", "f3"), "name": "F3", "tactic_refs": [ia["id"], mon["id"]]},
        ia, mon, *techs,
        rel(by["F1005.006"]["id"], "subtechnique-of", by["F1005"]["id"]),
    ]}


def atlas_doc():
    return {
        "format-version": "6.0.0",
        "collection": {"name": "ATLAS", "version": "2026.09"},
        "tactics": {"AML.TA0004": {"name": "Initial Access", "description": "Get in."}},
        "techniques": {
            "AML.T0051": {"name": "LLM Prompt Injection", "description": "Inject prompts.", "platforms": ["Generative AI"],
                          "maturity": "Realized", "attack-reference": {"id": "T1566", "url": "https://attack.mitre.org/techniques/T1566/"}},
            "AML.T0051.000": {"name": "Direct", "description": "Direct injection.", "platforms": ["Generative AI"]},
            "AML.T0073": {"name": "Impersonation", "description": "Impersonate.", "platforms": ["Enterprise"],
                          "attack-reference": {"id": "T1656", "url": "https://attack.mitre.org/techniques/T1656/"}},
        },
        "mitigations": {"AML.M0015": {"name": "Adversarial Input Detection", "description": "Detect.", "categories": ["Technical"]}},
        "case-studies": {"AML.CS0001": {"name": "Case One", "description": "A case."}},
        "relationships": {
            "AML.T0051": {"achieves": [{"source": "AML.T0051", "target": "AML.TA0004", "relationship-type": "achieves"}]},
            "AML.T0051.000": {"specializes": [{"source": "AML.T0051.000", "target": "AML.T0051", "relationship-type": "specializes"}]},
            "AML.M0015": {"mitigates": [{"source": "AML.M0015", "target": "AML.T0051", "relationship-type": "mitigates"}]},
            "AML.CS0001": {"employs": [{"source": "AML.CS0001", "target": "AML.T0051", "relationship-type": "employs",
                                        "step-id": "1", "tactic": "AML.TA0004", "description": "Step one."}]},
            "ATLAS": {"sequences": [{"source": "ATLAS", "target": "AML.TA0004", "relationship-type": "sequences", "position": 0}]},
        },
    }


D3FEND_TTL = """@prefix : <http://d3fend.mitre.org/ontologies/d3fend.owl#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<http://d3fend.mitre.org/ontologies/d3fend.owl> a owl:Ontology ; owl:versionInfo "9.9.9" .

:hardens a owl:ObjectProperty ; rdfs:label "hardens" .
:analyzes a owl:ObjectProperty ; rdfs:label "analyzes" .
:accesses a owl:ObjectProperty ; rdfs:label "accesses" .
:produces a owl:ObjectProperty ; rdfs:label "produces" .
:enables a owl:ObjectProperty ; rdfs:label "enables" .
:precedes a owl:ObjectProperty ; rdfs:label "precedes" .
:associated-with a owl:ObjectProperty ; rdfs:label "associated-with" .
:d3fend-id a owl:DatatypeProperty ; rdfs:label "d3fend-id" .

:DefensiveTactic a owl:Class ; rdfs:label "Defensive Tactic" .
:Harden a :DefensiveTactic, owl:Class ; rdfs:label "Harden" ; rdfs:subClassOf :DefensiveTactic ; :display-order 0 .
:Detect a :DefensiveTactic, owl:Class ; rdfs:label "Detect" ; rdfs:subClassOf :DefensiveTactic ; :display-order 1 .

:DefensiveTechnique a owl:Class ; rdfs:label "Defensive Technique" .
:CredentialHardening a owl:Class ; rdfs:label "Credential Hardening" ;
    rdfs:subClassOf :DefensiveTechnique,
        [ a owl:Restriction ; owl:onProperty :hardens ; owl:someValuesFrom :Credential ] ;
    :d3fend-id "D3-CH" ; :definition "Harden credentials." ; :enables :Harden .
:MultiFactorAuthentication a owl:Class ; rdfs:label "Multi-factor Authentication" ;
    rdfs:subClassOf :CredentialHardening ; :d3fend-id "D3-MFA" ; :definition "Use MFA." .
:URLAnalysis a owl:Class ; rdfs:label "URL Analysis" ;
    rdfs:subClassOf :DefensiveTechnique,
        [ a owl:Restriction ; owl:onProperty :enables ; owl:someValuesFrom :Detect ],
        [ a owl:Restriction ; owl:onProperty :analyzes ; owl:someValuesFrom :URL ] ;
    :d3fend-id " D3-UA" ; :definition "Analyze URLs." .
:ClusterAnalysis a owl:Class ; rdfs:label "Cluster Analysis" ; :d3fend-id "D3A-CA" ; :definition "An analytic method." .
:CorrelationAnalysis a owl:Class ; rdfs:label "Correlation Analysis" ; :d3fend-id "D3A-CA" ; :definition "Same ID upstream." .

:DigitalArtifact a owl:Class ; rdfs:label "Digital Artifact" .
:Credential a owl:Class ; rdfs:label "Credential" ; rdfs:subClassOf :DigitalArtifact .
:SessionCookie a owl:Class ; rdfs:label "Session Cookie" ; rdfs:subClassOf :Credential .
:URL a owl:Class ; rdfs:label "URL" ; rdfs:subClassOf :DigitalArtifact .

:T1539 a owl:Class ; rdfs:label "Steal Web Session Cookie" ; :attack-id "T1539" .
:T1566.002 a owl:Class ; rdfs:label "Spearphishing Link" ; :attack-id "T1566.002" .
:T1656 a owl:Class ; rdfs:label "Impersonation" ; :attack-id "T1656" .
:T0001 a owl:Class ; rdfs:label "Exploit Workstation" ; :attack-id "T0001" .
"""


def _row(off, d3_local, d3_label, tactic, def_rel, def_art, off_rel, off_art):
    lit = lambda v: {"type": "literal", "value": v}  # noqa: E731
    uri = lambda v: {"type": "uri", "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#" + v}  # noqa: E731
    return {"off_tech_id": lit(off), "def_tech": uri(d3_local), "def_tech_label": lit(d3_label),
            "def_tactic_label": lit(tactic), "def_artifact_rel_label": lit(def_rel), "def_artifact_rel": uri(def_rel),
            "def_artifact_label": lit(def_art), "def_artifact": uri(def_art.replace(" ", "")),
            "off_artifact_rel_label": lit(off_rel), "off_artifact_rel": uri(off_rel),
            "off_artifact_label": lit(off_art), "off_artifact": uri(off_art.replace(" ", ""))}


def mappings_doc():
    rows = [
        _row("T1539", "CredentialHardening", "Credential Hardening", "Harden", "hardens", "Credential", "accesses", "Session Cookie"),
        _row("T1539", "MultiFactorAuthentication", "Multi-factor Authentication", "Harden", "hardens", "Credential", "accesses", "Session Cookie"),
        _row("T1566.002", "URLAnalysis", "URL Analysis", "Detect", "analyzes", "URL", "produces", "URL"),
        _row("T1656", "CredentialHardening", "Credential Hardening", "Harden", "hardens", "Credential", "accesses", "Credential"),
        _row("CAPEC-66", "URLAnalysis", "URL Analysis", "Detect", "analyzes", "URL", "produces", "URL"),
    ]
    return {"head": {"vars": list(rows[0])}, "results": {"bindings": rows}}


def write_fixtures(root: Path, *, attack=None, ics=None, with_mappings=True) -> list[ResolvedSource]:
    root.mkdir(parents=True, exist_ok=True)
    (root / "enterprise.json").write_text(json.dumps(attack or attack_bundle()))
    (root / "ics.json").write_text(json.dumps(ics or ics_bundle()))
    (root / "f3.json").write_text(json.dumps(f3_bundle()))
    (root / "atlas.yaml").write_text(yaml.safe_dump(atlas_doc()))
    (root / "d3fend.ttl").write_text(D3FEND_TTL)
    (root / "mappings.json").write_text(json.dumps(mappings_doc()))
    sources = [
        ResolvedSource("attack-enterprise", None, str(root / "enterprise.json")),
        ResolvedSource("attack-ics", None, str(root / "ics.json")),
        ResolvedSource("f3", None, str(root / "f3.json")),
        ResolvedSource("atlas", None, str(root / "atlas.yaml")),
        ResolvedSource("d3fend-ontology", None, str(root / "d3fend.ttl")),
    ]
    sources.append(ResolvedSource("d3fend-mappings", None,
                                  str(root / ("mappings.json" if with_mappings else "absent.json")), optional=True))
    return sources


@pytest.fixture(scope="session")
def built(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("fixtures")
    db = root / "test.db"
    build(db, write_fixtures(root / "src"), root / "cache", log=lambda m: None)
    return db


@pytest.fixture(scope="session")
def c(built) -> Countermap:
    return Countermap(built)


@pytest.fixture(scope="session")
def detect_db(tmp_path_factory) -> Path:
    """The standard fixtures plus ``detection_objects()`` and ``ics_detection_objects()``, for the
    detection-model and coverage tests."""
    root = tmp_path_factory.mktemp("detect")
    db = root / "detect.db"
    build(db, write_fixtures(root / "src", attack=attack_bundle(extra_objects=detection_objects()),
                             ics=ics_bundle(extra_objects=ics_detection_objects())), root / "cache",
          log=lambda m: None)
    return db


@pytest.fixture(scope="session")
def c_detect(detect_db) -> Countermap:
    return Countermap(detect_db)


@pytest.fixture(scope="session")
def c_no_mappings(tmp_path_factory) -> Countermap:
    root = tmp_path_factory.mktemp("nomap")
    db = root / "nomap.db"
    build(db, write_fixtures(root / "src", with_mappings=False), root / "cache", log=lambda m: None)
    return Countermap(db)
