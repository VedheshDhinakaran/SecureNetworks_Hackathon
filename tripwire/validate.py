"""Self-validation (breach-and-attack-simulation lite).

Fresh, randomised attacks are generated, pushed through every available sensor, and each detection is
checked. A rule that silently stops working turns the health panel red. Run once or on an interval.
"""
from __future__ import annotations

import json
import random
import shutil
import time
from pathlib import Path

from . import engines as eng
from . import gen
from .config import CLASSES, OUT, load_catalog

HEALTH = OUT / "health.json"


def _canaries(seed: int, d: Path) -> dict[str, str]:
    r = random.Random(seed)
    d.mkdir(parents=True, exist_ok=True)
    ips = {c: f"10.0.9.{r.randint(10, 240)}" for c in CLASSES}
    t0 = gen.T0 + r.randint(0, 3600)
    made = {}
    c = gen.Cap(seed + 1); gen.sc_scan(c, t0, ips["scan"], ports=r.randint(800, 1500), pps=r.uniform(200, 800)); c.write(d / "canary_scan.pcap")
    c = gen.Cap(seed + 2); gen.sc_ssh(c, t0, ips["ssh_bruteforce"], n=r.randint(40, 80), interval=r.uniform(0.3, 1.0)); c.write(d / "canary_ssh_bruteforce.pcap")
    c = gen.Cap(seed + 3); gen.sc_smb(c, t0, ips["smb_admin"], r.choice([["ADMIN$"], ["C$"], ["IPC$", "C$"], ["d$"]])); c.write(d / "canary_smb_admin.pcap")
    c = gen.Cap(seed + 4); gen.sc_fuzz(c, t0, ips["web_fuzz"], n=r.randint(200, 400), rps=r.uniform(30, 80)); c.write(d / "canary_web_fuzz.pcap")
    for cls in CLASSES:
        made[cls] = f"canary_{cls}"
    return made


def run_canary(engines: list[str], seed: int | None = None, log=print) -> dict:
    seed = seed or int(time.time())
    d = OUT / "validation"
    if d.exists():
        shutil.rmtree(d)
    names = _canaries(seed, d)
    root = OUT / "validation_engines"
    if root.exists():
        shutil.rmtree(root)
    for e in engines:
        if e != "native":
            eng.run_engine(e, d, force=True, log=log, out_root=root)
    res: dict = {}
    for cls, name in names.items():
        res[cls] = {}
        for e in engines:
            ev = eng.events_for(e, d / f"{name}.pcap", out_dir=root / e if e != "native" else None)
            res[cls][e] = any(x["class"] == cls for x in ev)
    health = {}
    for cls, byeng in res.items():
        n = sum(byeng.values())
        health[cls] = {"engines": byeng, "status": "green" if n == len(byeng) else ("amber" if n else "red")}
    overall = "red" if any(h["status"] == "red" for h in health.values()) else (
        "amber" if any(h["status"] == "amber" for h in health.values()) else "green")
    out = {"checked_at": time.time(), "seed": seed, "overall": overall, "classes": health}
    OUT.mkdir(exist_ok=True)
    HEALTH.write_text(json.dumps(out, indent=1), encoding="utf-8")
    return out
