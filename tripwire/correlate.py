"""Incident correlation: raw alerts from every sensor -> one incident per attacker with a kill-chain story.

Risk score (0-10), deliberately simple so it can be explained to an analyst:
  base      = highest stage severity in the incident
  + 1.0     for every additional distinct kill-chain stage (a campaign, not a one-off)
  + 1.0     if the stages occurred in kill-chain order (recon -> discovery -> credentials -> lateral)
  + 1.0     if at least one stage was confirmed by two independent sensors (Suricata and Zeek)
  capped at 10.
"""
from __future__ import annotations

from collections import defaultdict

from .config import load_catalog

GAP_S = 900   # alerts from one source more than 15 minutes apart are separate incidents


def correlate(events: list[dict]) -> list[dict]:
    cat = load_catalog()["classes"]
    by_src: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e.get("src"):
            by_src[e["src"]].append(e)
    incidents: list[dict] = []
    for src, evs in by_src.items():
        evs.sort(key=lambda e: e["ts"])
        cluster: list[dict] = []
        for e in evs:
            if cluster and e["ts"] - cluster[-1]["ts"] > GAP_S:
                incidents.append(_build(src, cluster, cat))
                cluster = []
            cluster.append(e)
        if cluster:
            incidents.append(_build(src, cluster, cat))
    incidents.sort(key=lambda i: (-i["risk"], i["start"]))
    for n, inc in enumerate(incidents, 1):
        inc["id"] = f"INC-{n:03d}"
    return incidents


def _build(src: str, evs: list[dict], cat: dict) -> dict:
    stages: dict[str, dict] = {}
    for e in evs:
        s = stages.setdefault(e["class"], {"class": e["class"], "first_ts": e["ts"], "last_ts": e["ts"], "count": 0,
                                           "sensors": set(), "layers": set(), "rules": set(),
                                           "technique": e["technique"], "tactic": e["tactic"], "dport": e.get("dport", 0)})
        s["first_ts"] = min(s["first_ts"], e["ts"])
        s["last_ts"] = max(s["last_ts"], e["ts"])
        s["count"] += 1
        s["sensors"].add(e["sensor"])
        s["layers"].add(e["layer"])
        s["rules"].add(e["rule"])
    stage_list = sorted(stages.values(), key=lambda s: s["first_ts"])
    for s in stage_list:
        real = {x for x in s["sensors"] if x in ("suricata", "zeek")}
        s["confidence"] = "high" if len(real) >= 2 else "medium"
        s["title"] = cat[s["class"]]["title"]
        s["order"] = cat[s["class"]]["order"]
        for k in ("sensors", "layers", "rules"):
            s[k] = sorted(s[k])
    sev = max(cat[s["class"]]["severity"] for s in stage_list)
    in_order = [s["order"] for s in stage_list] == sorted(s["order"] for s in stage_list)
    consensus = any(s["confidence"] == "high" for s in stage_list)
    risk = sev + (len(stage_list) - 1) + (1 if in_order and len(stage_list) > 1 else 0) + (1 if consensus else 0)
    risk = round(min(10.0, float(risk)), 1)
    return {
        "src": src, "victims": sorted({e["dst"] for e in evs if e.get("dst")}),
        "start": stage_list[0]["first_ts"], "end": max(s["last_ts"] for s in stage_list),
        "stages": stage_list, "risk": risk,
        "severity": "critical" if risk >= 9 else "high" if risk >= 7 else "medium" if risk >= 4 else "low",
        "kill_chain_ordered": in_order, "alerts": len(evs),
        "pcaps": sorted({e.get("pcap", "") for e in evs if e.get("pcap")}),
        "summary": " -> ".join(s["title"] for s in stage_list),
    }
