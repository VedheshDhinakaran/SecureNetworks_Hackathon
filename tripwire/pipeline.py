"""Orchestration: dataset -> sensors -> normalise -> score -> correlate -> root cause -> respond -> state."""
from __future__ import annotations

import json
import time
from collections import Counter
from datetime import datetime, timezone

from . import engines as eng
from . import harness, rca, respond, validate
from .config import CLASSES, OUT, PCAPS, ensure_dirs, load_catalog
from .correlate import correlate
from .gen import load_manifest
from .rules import build_rules, lint_checks


def coverage(sc: dict, engines: list[str]) -> list[dict]:
    cat = load_catalog()
    out = []
    for cls in CLASSES:
        c = cat["classes"][cls]
        ens = sc["engines"]["ensemble"][cls]
        by = [e for e in engines if sc["engines"][e][cls]["recall"] == 1.0]
        out.append({"class": cls, "title": c["title"], "technique": c["technique"], "technique_name": c["technique_name"],
                    "tactic": c["tactic"], "tactic_id": c["tactic_id"], "recall": ens["recall"], "detected_by": by,
                    "d3fend": c["d3fend"], "mitigations": [{"id": m, "name": cat["mitigations"][m]} for m in c["mitigations"]],
                    "observed": c["observed"], "why": c["why"], "evasion": c["evasion"], "severity": c["severity"],
                    "l1": c.get("l1"), "l2": c.get("l2"), "tuning_note": c.get("tuning_note", "")})
    return out


def run(requested: list[str] | None = None, force: bool = False, canary: bool = True, log=print) -> dict:
    t_start = time.time()
    ensure_dirs()
    man = load_manifest()
    build_rules()
    avail = eng.availability()
    if requested:
        engines = [e for e in requested if e == "native" or avail.get(e) == "ok"] or ["native"]
    else:
        engines = ["native"] + [e for e in ("suricata", "zeek") if avail.get(e) == "ok"]
    log("Engines: " + ", ".join(f"{k}={v}" for k, v in avail.items()))
    for e in engines:
        if e != "native":
            eng.run_engine(e, force=force, log=log)
    log("Scoring ...")
    col = harness.collect(engines, man)
    sc = harness.score(col, man, engines)
    sw = harness.sweep(man)
    gate = harness.gate(sc, sw, engines) + lint_checks()

    # incidents from every attack-like capture, merged across sensors
    events = [x for m in man if m["kind"] in ("attack", "chain", "evasion") for e in engines for x in col[m["name"]][e]]
    events = [e for e in events if not e.get("aux")]
    events.sort(key=lambda e: e["ts"])
    incidents = correlate(events)
    pcap_of = {m["name"]: m for m in man}
    rcas = {}
    for inc in incidents:
        pc = inc["pcaps"][0] if inc["pcaps"] else None
        if not pc:
            continue
        ev = eng.evidence_for(PCAPS / pcap_of[pc]["file"])
        r = rca.analyse(inc, ev)
        rca.write_fixpack(r)
        rcas[inc["id"]] = r
    plan = respond.plan(incidents)
    respond.write_plan(plan)

    health = None
    if canary:
        log("Self-validation canaries ...")
        try:
            health = validate.run_canary(engines, log=log)
        except Exception as exc:                        # never let the canary break the main run
            log(f"  canary skipped: {exc}")
    elif validate.HEALTH.exists():
        health = json.loads(validate.HEALTH.read_text())

    kinds = Counter(m["kind"] for m in man)
    benign_min = round(sum(m["duration"] for m in man if m["kind"] == "benign") / 60, 1)
    state = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runtime_s": round(time.time() - t_start, 1),
        "meta": load_catalog()["meta"], "availability": avail, "engines": engines,
        "dataset": {"pcaps": len(man), "kinds": dict(kinds), "benign_minutes": benign_min,
                    "items": [{k: m[k] for k in ("name", "kind", "expect", "duration", "packets", "desc")} for m in man]},
        "score": sc, "agreement": harness.agreement(col, man, engines), "gate": gate, "sweep": sw,
        "grid": harness.robustness_grid(col, man, engines), "evasion": harness.evasion_matrix(col, man, engines),
        "coverage": coverage(sc, engines), "incidents": incidents, "rca": rcas, "response": plan, "health": health,
        "alerts": events[-500:],
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "state.json").write_text(json.dumps(state, indent=1, default=str), encoding="utf-8")
    return state
