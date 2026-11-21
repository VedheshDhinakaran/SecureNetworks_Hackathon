"""Command line: python -m tripwire <command>"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

from . import engines as eng
from . import report, rules, validate
from .config import OUT, ROOT, ensure_dirs
from .gen import build_dataset


def _line(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def summary(state: dict) -> None:
    sc = state["score"]
    print("\n=== Tripwire results " + "=" * 58)
    print(f"engines: {', '.join(state['engines'])}   captures: {state['dataset']['pcaps']}   "
          f"benign baseline: {state['dataset']['benign_minutes']} min   runtime: {state['runtime_s']}s")
    print("\nPer-class quality (ensemble of all sensors)")
    print(f"  {'class':16s} {'detected':>9s} {'recall':>7s} {'precision':>10s} {'false alerts':>13s} {'median TTD':>11s}")
    for c, v in sc["engines"]["ensemble"].items():
        ttd = f"{v['ttd_median_s']}s" if v["ttd_median_s"] is not None else "-"
        print(f"  {c:16s} {v['tp']:>4d}/{v['positives']:<4d} {v['recall']:>7} {v['precision']:>10} {v['fp_alerts']:>13d} {ttd:>11s}")
    print("\nThreshold sweep (chosen value vs measured safe band)")
    for k, v in state["sweep"].items():
        print(f"  {k:20s} chosen={v['current']:<4d} band={v['band'][0]}-{v['band'][1]:<5} noisiest benign={v['worst_benign']}({v['max_benign']}) -> {'ok' if v['in_band'] else 'OUTSIDE BAND'}")
    print("\nEvasion matrix")
    for r in state["evasion"]:
        hit = ", ".join(k for k, x in r["cells"].items() if x) or "nothing"
        print(f"  {r['pcap']:20s} caught by: {hit}{'   <-- known gap' if r['known_gap'] else ''}")
    print("\nIncidents")
    for i in state["incidents"][:6]:
        print(f"  {i['id']} {i['src']:12s} risk {i['risk']:>4} {i['severity']:8s} {i['summary']}")
    if state["rca"]:
        top = state["incidents"][0]
        r = state["rca"][top["id"]]
        print(f"\nRoot causes for {top['id']} ({r['evidence_source']}): {len(r['root_causes'])} confirmed, "
              f"{r['verification']['cleared']}/{r['verification']['total']} verified on patched config")
        for c in r["root_causes"][:4]:
            print(f"  {c['rank']}. [{c['confidence']}] {c['cause']}")
    if state.get("health"):
        print(f"\nSelf-validation canaries: {state['health']['overall'].upper()}")
    print("\nAcceptance gate")
    for g in state["gate"]:
        print(f"  [{_line(g['ok'])}] {g['name']}\n         {g['detail']}")
    print("=" * 80)


def cmd_test(a) -> int:
    from . import pipeline
    state = pipeline.run(a.engines, force=a.force, canary=not a.no_canary)
    paths = report.write_all(state)
    summary(state)
    print("\nOutputs:")
    for k, p in paths.items():
        print(f"  {k:10s} {p}")
    print(f"  fix packs  {OUT / 'fixpack'}\n  response   {OUT / 'response_plan.json'}")
    return 0 if all(g["ok"] for g in state["gate"]) else 1


def cmd_report(_a) -> int:
    state = json.loads((OUT / "state.json").read_text(encoding="utf-8"))
    for k, p in report.write_all(state).items():
        print(f"{k}: {p}")
    return 0


def cmd_gen(a) -> int:
    ensure_dirs()
    m = build_dataset(a.seed)
    print(f"wrote {len(m)} labelled PCAPs to data/pcaps and data/manifest.json")
    return 0


def cmd_rules(_a) -> int:
    for p in rules.build_rules():
        print("wrote", p)
    for c in rules.lint_checks():
        print(("PASS " if c["ok"] else "FAIL ") + c["name"] + " - " + c["detail"])
    return 0


def cmd_engines(_a) -> int:
    for k, v in eng.availability().items():
        print(f"{k:9s} {v}")
    return 0


def cmd_validate(a) -> int:
    av = eng.availability()
    engines = ["native"] + [e for e in ("suricata", "zeek") if av.get(e) == "ok"]
    while True:
        h = validate.run_canary(engines)
        print(time.strftime("%H:%M:%S"), "canaries:", h["overall"].upper(), {c: v["status"] for c, v in h["classes"].items()})
        if not a.interval:
            return 0 if h["overall"] == "green" else 1
        time.sleep(a.interval)


def cmd_serve(a) -> int:
    from .serve import serve
    serve(a.port, "tail" if a.tail else "replay", a.speed, a.only, host=a.host)
    return 0


def cmd_real(_a) -> int:
    """Score every real Docker-lab capture against its ground truth."""
    from . import real
    av = eng.availability()
    engines = ["native"] + [e for e in ("suricata", "zeek") if av.get(e) == "ok"]
    rows = real.evaluate(engines)
    if not rows:
        print("no real captures found (record them with the Docker lab; see lab/ssh_suite.sh)")
        return 1
    print(real.table(rows))
    bad = [r["name"] for r in rows if not r["ok"]]
    print(f"\n{len(rows) - len(bad)}/{len(rows)} real captures behave as expected" + (f"; check: {', '.join(bad)}" if bad else ""))
    return 1 if bad else 0


def cmd_analyze(a) -> int:
    """Analyse real captures (for example the Docker lab's data/real_pcaps) with every available sensor."""
    from pathlib import Path
    from . import native, rca
    from .correlate import correlate
    from .evidence import from_native, from_zeek
    d = Path(a.dir)
    pcaps = sorted(d.glob("*.pcap"))
    if not pcaps:
        print(f"no .pcap files in {d}")
        return 1
    av = eng.availability()
    engines = ["native"] + [e for e in ("suricata", "zeek") if av.get(e) == "ok"]
    root = OUT / "real"
    for e in engines:
        if e != "native":
            eng.run_engine(e, d, force=True, out_root=root)
    events = [x for p in pcaps for e in engines for x in eng.events_for(e, p, out_dir=(root / e) if e != "native" else None)]
    events = [e for e in events if not e.get("aux")]
    incs = correlate(events)
    print(f"{len(pcaps)} capture(s), engines: {', '.join(engines)}, {len(events)} alerts -> {len(incs)} incident(s)")
    for inc in incs:
        p = next(p for p in pcaps if p.stem == inc["pcaps"][0])
        ev = from_zeek(root / "zeek" / p.stem) or from_native(native.parse_pcap(p))
        r = rca.analyse(inc, ev)
        print()
        print(f"{inc['id']} {inc['src']} risk {inc['risk']} ({inc['severity']}): {inc['summary']}")
        for c in r["root_causes"][:5]:
            print(f"  {c['rank']}. [{c['confidence']}] {c['cause']}")
            print(f"       fix: {c['fix']['short_term']}")
    return 0


def cmd_lab(a) -> int:
    base = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml")]
    table = {"up": base + ["up", "-d", "--build"], "down": base + ["down", "-v"],
             "attack": base + ["exec", "attacker", "/lab/run_all.sh"], "logs": base + ["logs", "--tail", "50"]}
    return subprocess.call(table[a.action])


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(prog="tripwire", description="Tripwire: detect, correlate, explain, fix, verify.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("test", help="run everything and apply the acceptance gate (exit 1 on failure)")
    p.add_argument("--engines", nargs="*", help="subset of: native suricata zeek (default: all available)")
    p.add_argument("--force", action="store_true", help="re-run Suricata/Zeek even if cached")
    p.add_argument("--no-canary", action="store_true", help="skip the self-validation canaries")
    p.set_defaults(fn=cmd_test)
    sub.add_parser("report", help="rebuild dashboard and documents from the last run").set_defaults(fn=cmd_report)
    p = sub.add_parser("gen", help="regenerate the labelled PCAP dataset")
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(fn=cmd_gen)
    sub.add_parser("build-rules", help="render Suricata rules and the Zeek script from the catalog").set_defaults(fn=cmd_rules)
    sub.add_parser("engines", help="show which sensors are available").set_defaults(fn=cmd_engines)
    p = sub.add_parser("validate", help="self-validation: fresh randomised attacks must still be detected")
    p.add_argument("--interval", type=int, default=0, help="repeat every N seconds")
    p.set_defaults(fn=cmd_validate)
    p = sub.add_parser("serve", help="live dashboard")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 inside Docker")
    p.add_argument("--tail", action="store_true", help="follow live sensor logs in data/live (Docker lab)")
    p.add_argument("--speed", type=float, default=30.0, help="replay clock speed-up")
    p.add_argument("--only", nargs="*", help="replay only these captures, e.g. attack_chain")
    p.set_defaults(fn=cmd_serve)
    sub.add_parser("real", help="score the real Docker-lab captures against their ground truth").set_defaults(fn=cmd_real)
    p = sub.add_parser("analyze", help="detect, correlate and explain real captures in a folder")
    p.add_argument("dir", nargs="?", default="data/real_pcaps")
    p.set_defaults(fn=cmd_analyze)
    p = sub.add_parser("lab", help="Docker lab helper")
    p.add_argument("action", choices=["up", "down", "attack", "logs"])
    p.set_defaults(fn=cmd_lab)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
