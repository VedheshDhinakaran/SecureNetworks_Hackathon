"""Real-lab capture evaluation: every PCAP recorded from the Docker lab, scored against its ground truth.

The synthetic dataset proves repeatability. These captures prove the detections work on traffic from real tools
(hydra, nmap, ffuf, smbclient) and real servers (OpenSSH, Samba, nginx). Zeek's SSH attempt inference, for
example, only works on genuine SSH traffic, so it can only be validated here.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import engines as eng
from .config import DATA, OUT

REAL_DIR = DATA / "real_pcaps"
REAL_MANIFEST = DATA / "real_manifest.json"


def load() -> list[dict]:
    if not REAL_MANIFEST.exists():
        return []
    return [m for m in json.loads(REAL_MANIFEST.read_text(encoding="utf-8")) if (REAL_DIR / f"{m['name']}.pcap").exists()]


def evaluate(engines: list[str], run: bool = True, log=print) -> list[dict]:
    """One row per real capture: what each sensor saw, and whether that matches the ground truth."""
    man = load()
    if not man:
        return []
    root = OUT / "real"
    if run:
        for e in engines:
            if e != "native":
                eng.run_engine(e, REAL_DIR, force=True, log=log, out_root=root)
    rows = []
    for m in man:
        p = REAL_DIR / f"{m['name']}.pcap"
        seen: dict[str, list[str]] = {}
        for e in engines:
            ev = eng.events_for(e, p, out_dir=(root / e) if e != "native" else None)
            seen[e] = sorted({x["class"] for x in ev if not x.get("aux")})
        union = {c for v in seen.values() for c in v}
        expect = set(m["expect"])
        gap = bool(m.get("known_gap"))
        missed, extra = sorted(expect - union), sorted(union - expect)
        if gap:
            verdict = "known gap" if missed else "caught (better than expected)"
        elif not expect:
            verdict = "clean" if not union else "FALSE ALERT"
        else:
            verdict = "detected" if not missed else "MISSED"
            if extra:
                verdict += " + extra alerts"
        rows.append({"name": m["name"], "kind": m["kind"], "desc": m["desc"], "expect": m["expect"], "seen": seen,
                     "missed": missed, "extra": extra, "known_gap": gap, "verdict": verdict,
                     "ok": verdict in ("clean", "detected", "known gap", "caught (better than expected)")})
    OUT.mkdir(exist_ok=True)
    (OUT / "real_results.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return rows


def table(rows: list[dict]) -> str:
    engines = list(rows[0]["seen"]) if rows else []
    short = {"web_fuzz": "fuzz", "scan": "scan", "ssh_bruteforce": "ssh", "smb_admin": "smb"}
    head = f"  {'capture':24s} {'expected':14s} " + " ".join(f"{e:12s}" for e in engines) + " verdict"
    out = [head]
    for r in rows:
        exp = ",".join(short[c] for c in r["expect"]) or "nothing"
        cols = " ".join(f"{(','.join(short[c] for c in r['seen'][e]) or '-'):12s}" for e in engines)
        out.append(f"  {r['name']:24s} {exp:14s} {cols} {r['verdict']}")
    return "\n".join(out)


# ---------------------------------------------------------------- SSH attempt threshold (real captures)
def _jsonl(path: Path):
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def ssh_attempt_metric(name: str, window: float = 120.0) -> dict:
    """Peak inferred password attempts in FAILED sessions inside a sliding window, per source-destination pair.
    Mirrors the Zeek rule: a session is credited when its final result is known (start + duration); successful
    and unknown sessions count zero."""
    d = OUT / "real" / "zeek" / name
    dur = {r["uid"]: r.get("duration") or 0 for r in _jsonl(d / "conn.log")}
    by_pair: dict[tuple, list] = {}
    failed = attempts = 0
    for r in _jsonl(d / "ssh.log"):
        if r.get("auth_success") is False and (r.get("auth_attempts") or 0) > 0:
            by_pair.setdefault((r["id.orig_h"], r["id.resp_h"]), []).append((r["ts"] + dur.get(r["uid"], 0), r["auth_attempts"]))
            failed += 1
            attempts += r["auth_attempts"]
    peak = 0
    for evs in by_pair.values():
        evs.sort()
        for i, (t, _) in enumerate(evs):
            peak = max(peak, sum(a for tt, a in evs if t - window <= tt <= t))
    return {"peak": peak, "failed_sessions": failed, "failed_attempts": attempts}


def ssh_attempt_sweep(rows: list[dict], thresholds=(5, 8, 12)) -> dict | None:
    """Retrospective threshold comparison on the real captures (the independent study compared 5, 8 and 12)."""
    from .config import load_catalog
    zeek_ok = any("zeek" in r["seen"] for r in rows)
    if not rows or not zeek_ok or not (OUT / "real" / "zeek").exists():
        return None
    cur = load_catalog()["classes"]["ssh_bruteforce"]["attempts"]
    items = []
    for r in rows:
        if (OUT / "real" / "zeek" / r["name"]).exists():
            m = ssh_attempt_metric(r["name"], cur["window"])
            role = "gap" if r["known_gap"] else ("attack" if "ssh_bruteforce" in r["expect"] else ("control" if not r["expect"] else "other"))
            if role != "other":
                items.append({"name": r["name"], "role": role, "desc": r["desc"], **m})
    pos = [i["peak"] for i in items if i["role"] == "attack"]
    neg = [i["peak"] for i in items if i["role"] == "control"]
    if not pos or not neg:
        return None
    lo, hi = max(neg) + 1, min(pos)
    for i in items:
        i["detected"] = {str(t): i["peak"] >= t for t in thresholds}
    return {"current": cur["count"], "window": cur["window"], "band": [lo, hi], "in_band": lo <= cur["count"] <= hi,
            "max_control": max(neg), "min_attack": min(pos), "thresholds": list(thresholds), "items": items,
            "summary": {str(t): {"attacks": sum(1 for i in items if i["role"] == "attack" and i["peak"] >= t),
                                 "of_attacks": sum(1 for i in items if i["role"] == "attack"),
                                 "false_alerts": sum(1 for i in items if i["role"] == "control" and i["peak"] >= t),
                                 "gap_caught": sum(1 for i in items if i["role"] == "gap" and i["peak"] >= t)} for t in thresholds}}


def gate_checks(rows: list[dict], sweep: dict | None, engines: list[str]) -> list[dict]:
    """Acceptance checks on real traffic. Needs Zeek: SSH attempt inference exists only there."""
    if not rows or "zeek" not in engines:
        return []
    bad = [r["name"] for r in rows if not r["ok"]]
    checks = [{"name": "Real lab: every real capture behaves as its ground truth says (detected, clean, or documented gap)",
               "ok": not bad, "detail": f"{len(rows) - len(bad)}/{len(rows)} real captures as expected" + (f"; check {bad}" if bad else "")}]
    if sweep:
        checks.append({"name": "Tuning: SSH attempt threshold sits inside its band measured on real captures",
                       "ok": sweep["in_band"], "detail": f"chosen {sweep['current']}, band {sweep['band'][0]}-{sweep['band'][1]} "
                       f"(noisiest control {sweep['max_control']}, weakest attack {sweep['min_attack']})"})
    return checks
