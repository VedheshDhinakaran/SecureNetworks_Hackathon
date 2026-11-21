"""Auto-generated deliverables: dashboard, ATT&CK Navigator layer, report, detection-logic document."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .config import OUT, ROOT, load_catalog

DASH = Path(__file__).with_name("dashboard.html")
DOCS = ROOT / "docs"
TACTIC_SHORT = {"Reconnaissance": "reconnaissance", "Discovery": "discovery", "Credential Access": "credential-access",
                "Lateral Movement": "lateral-movement"}


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")


# ------------------------------------------------------------------ dashboard
def write_dashboard(state: dict, path: Path | None = None) -> Path:
    path = path or OUT / "dashboard.html"
    html = DASH.read_text(encoding="utf-8")
    blob = json.dumps(state, default=str).replace("</", "<\\/")
    html = html.replace("/*__STATE__*/null", blob)
    path.write_text(html, encoding="utf-8")
    return path


# ------------------------------------------------------------------ Navigator layer
def navigator_layer(state: dict) -> dict:
    cat = load_catalog()
    av = str(cat["meta"].get("attack_version", ""))
    techniques = []
    for c in state["coverage"]:
        n = len(c["detected_by"])
        both = n >= 2
        techniques.append({
            "techniqueID": c["technique"], "tactic": TACTIC_SHORT[c["tactic"]], "enabled": True,
            "score": 100 if both else 60 if n == 1 else 0,
            "color": "#2e9d57" if both else "#d9a521" if n == 1 else "#c0392b",
            "comment": (f"Detected by: {', '.join(c['detected_by']) or 'none'}. Recall {c['recall']}. "
                        f"Mitigations: {', '.join(m['id'] for m in c['mitigations'])}. D3FEND: {', '.join(c['d3fend'])}.")})
    return {"name": "Tripwire detection coverage",
            "versions": {"attack": av if av.isdigit() else "16", "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Generated from detections/catalog.yml and measured results. Confirm the ATT&CK version before submitting.",
            "sorting": 0, "layout": {"layout": "side", "showName": True, "showID": True},
            "hideDisabled": False, "techniques": techniques,
            "gradient": {"colors": ["#c0392b", "#d9a521", "#2e9d57"], "minValue": 0, "maxValue": 100},
            "legendItems": [{"label": "Detected by two engines", "color": "#2e9d57"}, {"label": "One engine", "color": "#d9a521"}]}


# ------------------------------------------------------------------ markdown
def detection_logic_md() -> str:
    cat = load_catalog()
    out = ["# Detection logic", "",
           "Generated from `detections/catalog.yml`. Two layers: **L1** (Suricata, short window, fast) and "
           "**L2** (Zeek and native, long window, catches slow and low attacks).", ""]
    for cls, c in cat["classes"].items():
        out += [f"## {c['title']} ({c['technique']} {c['technique_name']})", "",
                f"- **Tactic:** {c['tactic']} ({c['tactic_id']})",
                f"- **What is observed:** {c['observed']}",
                f"- **Why it indicates the behavior:** {c['why']}"]
        if "l1" in c:
            l1, l2 = c["l1"], c["l2"]
            out.append(f"- **Layer 1 (Suricata sid {c['sid']}, a rate rule):** {l1['count']} events within {l1['window']} s")
            if cls == "web_fuzz":
                out.append(f"- **Layer 2 (Zeek, contextual):** at least {l2['errors']} 403/404 replies AND at least {l2['count']} distinct failing paths "
                           f"(query strings removed) AND an error ratio of at least {l2['ratio']}, in a sliding {l2['window']} s window per source-destination service")
            elif cls == "scan":
                out.append(f"- **Layer 2 (Zeek):** {l2['count']} distinct destination ports of one target within a sliding {l2['window']} s window "
                           "(answered, refused or silently dropped probes all count)")
            else:
                out.append(f"- **Layer 2 (Zeek):** {l2['count']} new connections within {l2['window']} s")
            if "attempts" in c:
                a = c["attempts"]
                out.append(f"- **Attempt layer (Zeek only):** {a['count']} INFERRED password attempts in failed SSH sessions within a sliding {a['window']} s window "
                           "per source-destination pair; successful and unknown sessions count zero (an estimate from encrypted packet sizes, not ground truth)")
        else:
            out.append(f"- **Signature:** tree-connect to an administrative share (Suricata sids {c['sid']}, {c['sid_aux']}; Zeek notice)")
        out += [f"- **Known evasion:** {c['evasion']}",
                f"- **D3FEND:** {', '.join(c['d3fend'])}",
                f"- **Mitigations:** {', '.join(cat['mitigations'][m] + ' (' + m + ')' for m in c['mitigations'])}"]
        if c.get("tuning_note"):
            out.append(f"- **Tuning note:** {c['tuning_note']}")
        out.append("")
    return "\n".join(out)


def report_md(state: dict) -> str:
    sc = state["score"]
    L = [f"# Tripwire results report", "",
         f"Generated {state['generated']} in {state['runtime_s']} s. Engines used: **{', '.join(state['engines'])}**.",
         f"Dataset: {state['dataset']['pcaps']} labelled captures ({state['dataset']['benign_minutes']} min benign baseline, "
         f"{state['dataset']['kinds'].get('hardneg', 0)} hard-negative captures).", "", "## Acceptance gate", ""]
    for g in state["gate"]:
        L.append(f"- {'PASS' if g['ok'] else 'FAIL'}: {g['name']} ({g['detail']})")
    L += ["", "## True and false positives per class", "",
          "| Engine | Class | Attacks | TP | FN | FP alerts (benign) | Recall | Precision | Median time to detect |",
          "|---|---|---|---|---|---|---|---|---|"]
    for en, per in sc["engines"].items():
        for cls, v in per.items():
            ttd = f"{v['ttd_median_s']} s" if v["ttd_median_s"] is not None else "-"
            L.append(f"| {en} | {cls} | {v['positives']} | {v['tp']} | {v['fn']} | {v['fp_alerts']} | {v['recall']} | {v['precision']} | {ttd} |")
    L += ["", "## Threshold sweep (evidence-based tuning)", "",
          "| Class.layer | Chosen | Safe band | Highest benign | Lowest attack | In band |", "|---|---|---|---|---|---|"]
    for k, v in state["sweep"].items():
        L.append(f"| {k} | {v['current']} | {v['band'][0]}-{v['band'][1]} | {v['max_benign']} ({v['worst_benign']}) | {v['min_attack']} ({v['weakest_attack']}) | {'yes' if v['in_band'] else 'NO'} |")
    if state.get("real"):
        engs = list(state["real"][0]["seen"])
        L += ["", "## Real Docker-lab captures", "",
              "Traffic recorded from real tools (hydra, nmap, ffuf, smbclient) against real servers, scored against ground truth.", "",
              "| Capture | What happened | Expected | " + " | ".join(engs) + " | Verdict |", "|---|---|---|" + "---|" * len(engs) + "---|"]
        for r in state["real"]:
            cols = " | ".join(", ".join(r["seen"][e]) or "-" for e in engs)
            L.append(f"| {r['name']} | {r['desc']} | {', '.join(r['expect']) or 'nothing'} | {cols} | {r['verdict']} |")
    L += ["", "## Evasion matrix", "", "| Case | Description | Caught by | Note |", "|---|---|---|---|"]
    for r in state["evasion"]:
        hit = [k for k, x in r["cells"].items() if x]
        L.append(f"| {r['pcap']} | {r['desc']} | {', '.join(hit) or 'nothing'} | {'KNOWN GAP (see limitations)' if r['known_gap'] else ''} |")
    L += ["", "## Incidents and root causes", ""]
    for inc in state["incidents"][:6]:
        r = state["rca"].get(inc["id"])
        L += [f"### {inc['id']} source {inc['src']}: {inc['summary']}", f"Risk {inc['risk']} ({inc['severity']}), {inc['alerts']} alerts.", ""]
        if r:
            for c in r["root_causes"][:5]:
                L.append(f"{c['rank']}. **{c['cause']}** (confidence {c['confidence']}; {c['mitigation']} {c['mitigation_name']}). Fix: {c['fix']['short_term']}")
            v = r["verification"]
            L.append(f"\nVerification: {v['cleared']} of {v['total']} causes cleared on the patched config copy; the rest need a live re-attack.\n")
    L += ["## ATT&CK mapping", "", "| Technique | Tactic | Detected by | Mitigations | D3FEND |", "|---|---|---|---|---|"]
    for c in state["coverage"]:
        L.append(f"| {c['technique']} {c['technique_name']} | {c['tactic']} | {', '.join(c['detected_by'])} | {', '.join(m['id'] for m in c['mitigations'])} | {', '.join(c['d3fend'])} |")
    L += ["", "## Limitations (stated honestly)", "",
          "- Detection by per-source counting cannot see attacks spread over many source addresses (ev_distributed_ssh).",
          "- Encrypted SSH hides login success; the platform labels this finding as a heuristic and confirms from host logs when available.",
          "- SMB3 encryption would hide share names from both sensors.",
          "- Synthetic traffic proves repeatability and measures the detection envelope; the Docker lab captures authentic traffic.",
          "- Root cause analysis is rule-based hypothesis testing against the lab's real config files, not causal inference.",
          "- MITRE IDs come from the hackathon brief; confirm them against the current ATT&CK release."]
    return "\n".join(L)


def write_all(state: dict) -> dict[str, Path]:
    OUT.mkdir(exist_ok=True)
    DOCS.mkdir(exist_ok=True)
    paths = {"dashboard": write_dashboard(state)}
    paths["navigator"] = OUT / "attack_navigator_layer.json"
    paths["navigator"].write_text(json.dumps(navigator_layer(state), indent=1), encoding="utf-8")
    paths["report"] = OUT / "REPORT.md"
    paths["report"].write_text(report_md(state), encoding="utf-8")
    paths["logic"] = DOCS / "DETECTION_LOGIC.md"
    paths["logic"].write_text(detection_logic_md(), encoding="utf-8")
    return paths
