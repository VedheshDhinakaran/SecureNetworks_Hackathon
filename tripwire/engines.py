"""Sensor runners: Suricata and Zeek (via Docker) and the native detector, all normalised to one schema.

Normalised event:
  ts, sensor (suricata|zeek|native), layer (L1|L2), class, rule, name, src (attacker), dst (victim),
  dport, technique, tactic, severity, detail, pcap
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime
from pathlib import Path

from . import native
from .config import OUT, PCAPS, RULES_DIR, ZEEK_DIR, load_catalog
from .evidence import Evidence, from_native, from_zeek

IMAGES = {"suricata": "jasonish/suricata", "zeek": "zeek/zeek"}
ZEEK_NOTES = {"Tripwire::Port_Scan": "scan", "Tripwire::SSH_Bruteforce": "ssh_bruteforce",
              "Tripwire::Web_Fuzz": "web_fuzz", "Tripwire::SMB_Admin_Share": "smb_admin"}


# ------------------------------------------------------------------ availability
def _run(cmd: list[str], timeout: int = 20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def availability() -> dict[str, str]:
    """engine -> 'ok' or the reason it is unavailable. Native is always available."""
    st = {"native": "ok"}
    if _run(["docker", "info"], 15).returncode != 0:
        for e in IMAGES:
            st[e] = "docker daemon not running"
        return st
    for e, img in IMAGES.items():
        st[e] = "ok" if _run(["docker", "image", "inspect", img], 15).returncode == 0 else f"image {img} not pulled"
    return st


# ------------------------------------------------------------------ running
def _hash(parts: list[Path]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def _mount(src: Path, dst: str, ro: bool = True) -> list[str]:
    return ["--mount", f"type=bind,source={src.resolve()},target={dst}" + (",readonly" if ro else "")]


def run_engine(engine: str, pcap_dir: Path = PCAPS, force: bool = False, log=print, out_root: Path | None = None) -> Path:
    """Run one sensor over every PCAP in a directory (one container, many files)."""
    out = (out_root or OUT / "engines") / engine
    out.mkdir(parents=True, exist_ok=True)
    pcaps = sorted(pcap_dir.glob("*.pcap"))
    stamp = _hash(([RULES_DIR / "tripwire.rules"] if engine == "suricata" else [ZEEK_DIR / "tripwire.zeek"]) + pcaps)
    marker = out / ".hash"
    if not force and marker.exists() and marker.read_text() == stamp:
        log(f"  {engine}: cached ({len(pcaps)} pcaps)")
        return out
    cat = load_catalog()
    if engine == "suricata":
        script = ('for f in /pcap/*.pcap; do n=$(basename "$f" .pcap); rm -rf /out/$n; mkdir -p /out/$n; '
                  'suricata --runmode single -c /etc/suricata/suricata.yaml -S /rules/tripwire.rules -r "$f" -l /out/$n -k none '
                  f'--set vars.address-groups.HOME_NET="[{cat["meta"]["home_net"]}]" > /out/$n/stdout.txt 2>&1; done')
        mounts = _mount(pcap_dir, "/pcap") + _mount(RULES_DIR, "/rules") + _mount(out, "/out", ro=False)
    else:
        script = ('for f in /pcap/*.pcap; do n=$(basename "$f" .pcap); rm -rf /out/$n; mkdir -p /out/$n; cd /out/$n; '
                  'zeek -C -r "$f" /zeek/tripwire.zeek > /out/$n/stdout.txt 2>&1; done')
        mounts = _mount(pcap_dir, "/pcap") + _mount(ZEEK_DIR, "/zeek") + _mount(out, "/out", ro=False)
    log(f"  {engine}: running on {len(pcaps)} pcaps in {IMAGES[engine]} ...")
    r = _run(["docker", "run", "--rm", "--entrypoint", "/bin/sh", *mounts, IMAGES[engine], "-c", script], timeout=1800)
    if r.returncode != 0:
        raise RuntimeError(f"{engine} run failed: {r.stderr[-500:]}")
    marker.write_text(stamp)
    return out


# ------------------------------------------------------------------ parsing
def aggregate(events: list[dict], gap: float = 60.0) -> list[dict]:
    """Collapse bursts: repeated alerts for the same (sensor, rule, source) within `gap` seconds become one
    event with a count. detection_filter alerts on every packet past the threshold; analysts want one line."""
    out: list[dict] = []
    last: dict[tuple, dict] = {}
    for e in sorted(events, key=lambda x: x["ts"]):
        k = (e["sensor"], e["rule"], e["src"], e.get("dport"))
        prev = last.get(k)
        if prev and e["ts"] - prev["_last"] <= gap:
            prev["count"] += 1
            prev["_last"] = e["ts"]
            continue
        e = dict(e, count=1, _last=e["ts"])
        last[k] = e
        out.append(e)
    for e in out:
        e.pop("_last", None)
    return out

def _ts(s: str) -> float:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def parse_suricata(d: Path, pcap: str) -> list[dict]:
    cat = load_catalog()
    cls_cat = cat["classes"]
    home = cat["meta"]["victim_ip"].rsplit(".", 1)[0] + "."
    ev: list[dict] = []
    f = d / "eve.json"
    if not f.exists():
        return ev
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        if j.get("event_type") != "alert":
            continue
        ev.append(normalize_suricata(j, pcap, cls_cat, home))
    return aggregate([e for e in ev if e])


def normalize_suricata(j: dict, pcap: str, cls_cat: dict | None = None, home: str = "10.0.0.") -> dict | None:
    cls_cat = cls_cat or load_catalog()["classes"]
    a = j.get("alert", {})
    md = a.get("metadata", {}) or {}
    cls = (md.get("tripwire_class") or [None])[0]
    if cls not in cls_cat:
        return None
    src, dst = j.get("src_ip", ""), j.get("dest_ip", "")
    if src.startswith(home) and not dst.startswith(home):
        src, dst = dst, src                       # response-direction rule: attacker is the destination
    c = cls_cat[cls]
    aux = "(aux)" in a.get("signature", "")
    return {"ts": _ts(j["timestamp"]), "sensor": "suricata", "layer": (md.get("tripwire_layer") or ["L1"])[0],
            "class": cls, "rule": f"sid:{a.get('signature_id')}", "name": a.get("signature", ""), "aux": aux,
            "src": src, "dst": dst, "dport": j.get("dest_port") or 0, "technique": c["technique"],
            "tactic": c["tactic"], "severity": c["severity"], "detail": a.get("category", ""), "pcap": pcap}


def parse_zeek(d: Path, pcap: str) -> list[dict]:
    cls_cat = load_catalog()["classes"]
    out: list[dict] = []
    f = d / "notice.log"
    if not f.exists():
        return out
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(normalize_zeek_notice(j, pcap, cls_cat))
    return [e for e in out if e]


def normalize_zeek_notice(j: dict, pcap: str, cls_cat: dict | None = None) -> dict | None:
    cls_cat = cls_cat or load_catalog()["classes"]
    cls = ZEEK_NOTES.get(j.get("note", ""))
    if not cls:
        return None
    c = cls_cat[cls]
    return {"ts": float(j["ts"]), "sensor": "zeek", "layer": "L2", "class": cls, "rule": j["note"],
            "name": j.get("msg", j["note"]), "aux": False, "src": j.get("src", ""), "dst": j.get("dst", ""),
            "dport": j.get("p") or 0, "technique": c["technique"], "tactic": c["tactic"],
            "severity": c["severity"], "detail": j.get("msg", ""), "pcap": pcap}


# ------------------------------------------------------------------ public API
def events_for(engine: str, pcap_path: Path, out_dir: Path | None = None) -> list[dict]:
    name = pcap_path.stem
    if engine == "native":
        return native.detect(native.parse_pcap(pcap_path))
    d = (out_dir or OUT / "engines" / engine) / name
    return parse_suricata(d, name) if engine == "suricata" else parse_zeek(d, name)


def evidence_for(pcap_path: Path, prefer_zeek: bool = True) -> Evidence:
    if prefer_zeek:
        ev = from_zeek(OUT / "engines" / "zeek" / pcap_path.stem)
        if ev is not None:
            return ev
    return from_native(native.parse_pcap(pcap_path))
