"""Root cause analysis and fix engine.

Deterministic hypothesis testing, not guesswork. Each playbook hypothesis is a claim
("SSH password authentication is enabled") with one or more tests:
  * config tests read the victim's real config files (lab/victim/conf)
  * evidence tests query what the attacker demonstrably did (Zeek logs, or the PCAP)
A cause is CONFIRMED when its tests agree it is bad, with confidence from how many independent
tests agree. Every confirmed cause carries a three-tier fix, an ATT&CK mitigation and a config patch.
Fixes are applied to a COPY of the configs and the config tests are re-run to verify them.
"""
from __future__ import annotations

import difflib
import ipaddress
import re
import shutil
from pathlib import Path

import yaml

from .config import LAB_CONF, OUT, PLAYBOOKS, load_catalog
from .evidence import Evidence

HOSTLOG = Path(__file__).resolve().parents[1] / "data" / "hostlogs" / "auth.log"


# ------------------------------------------------------------------ config reading
def _read(conf_dir: Path, name: str) -> str | None:
    p = conf_dir / name
    return p.read_text(encoding="utf-8") if p.exists() else None


def read_directive(text: str, key: str, section: str | None = None) -> str | None:
    cur = None
    pat = re.compile(r"^\s*" + r"\s+".join(map(re.escape, key.split())) + r"\s*(?:=|\s)\s*(.+?)\s*;?\s*$", re.I)
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^\[(.+)\]$", s)
        if m:
            cur = m.group(1).lower()
            continue
        if section is not None and (cur or "") != section.lower():
            continue
        m = pat.match(line)
        if m:
            return m.group(1).strip()
    return None


def section_exists(text: str, section: str) -> bool:
    return any(l.strip().lower() == f"[{section.lower()}]" for l in text.splitlines())


# ------------------------------------------------------------------ evidence functions
def _mgmt():
    return ipaddress.ip_network(load_catalog()["meta"]["mgmt_subnet"])


def ev_src_outside_mgmt(ev: Evidence, src: str, **_):
    if ipaddress.ip_address(src) in _mgmt():
        return False, f"{src} is inside the management subnet"
    return True, f"{src} is outside the management subnet {_mgmt()} yet reached server services"


def ev_open_ports_exposed(ev: Evidence, src: str, allowed=(80, 443), **_):
    op = ev.open_ports(src)
    if not ev.conns.get(src):
        return None, "no connection evidence"
    extra = [p for p in op if p not in allowed]
    return bool(extra), f"{src} probed {len(ev.probed_ports(src))} ports; services answered on {op}; unexpected: {extra}"


def ev_smb_admin_reached(ev: Evidence, src: str, **_):
    """Bad only if the server actually granted an administrative share (or the outcome is unknown)."""
    oc = ev.smb_admin_outcomes(src)
    if not oc:
        return False, "no administrative share access seen"
    granted = [p for p, o in oc.items() if o == "granted"]
    unknown = [p for p, o in oc.items() if o in (None, "unknown")]
    if granted or unknown:
        return True, f"server granted tree-connect to {', '.join(granted + unknown)}"
    return False, "administrative shares were requested but the server refused: " + ", ".join(f"{p} ({o})" for p, o in oc.items())


def ev_hidden_paths_exposed(ev: Evidence, src: str, **_):
    hits = ev.http_hits(src)
    if not ev.http.get(src):
        return None, "no HTTP evidence"
    return bool(hits), (f"{len(hits)} guessed paths answered: " + ", ".join(f"{u} ({s})" for u, s in hits[:6])) if hits else "no guessed path answered"


def ev_attempts_unthrottled(ev: Evidence, src: str, min=20, **_):
    n = ev.ssh_attempts(src)
    return n >= min, f"{n} SSH connection attempts accepted from {src} without throttling"


EVIDENCE_FNS = {"src_outside_mgmt": ev_src_outside_mgmt, "open_ports_exposed": ev_open_ports_exposed,
                "smb_admin_reached": ev_smb_admin_reached, "hidden_paths_exposed": ev_hidden_paths_exposed,
                "attempts_unthrottled": ev_attempts_unthrottled}


# ------------------------------------------------------------------ impact
def impact(kind: str, ev: Evidence, src: str) -> dict:
    if kind == "ssh_login_probable":
        hit = ev.ssh_possible_success(src)
        host = _host_confirmed(src)
        if host:
            return {"level": "confirmed", "text": f"Host log confirms an accepted SSH login from {src}: {host}", "source": "host auth.log"}
        if hit:
            return {"level": "probable", "text": (f"After {hit['failed_before']} short failed sessions, one session lasted "
                    f"{hit['duration_s']} s and moved {hit['bytes']} bytes: the pattern of a successful login "
                    "(heuristic: SSH is encrypted, confirm in auth.log)"), "source": ev.source}
        return {"level": "none", "text": "No sign of a successful login in the network data", "source": ev.source}
    if kind == "smb_admin_reached":
        oc = ev.smb_admin_outcomes(src)
        if not oc:
            return {"level": "none", "text": "No administrative share requested", "source": ev.source}
        granted = [p for p, o in oc.items() if o == "granted"]
        refused = [f"{p} ({o})" for p, o in oc.items() if o in ("denied", "error")]
        unknown = [p for p, o in oc.items() if o in (None, "unknown")]
        if granted:
            txt = "Server GRANTED access to " + ", ".join(granted) + (("; refused: " + ", ".join(refused)) if refused else "")
            return {"level": "confirmed", "text": txt, "source": ev.source}
        if refused and not unknown:
            return {"level": "attempted", "text": "Administrative share(s) requested but refused by the server: " + ", ".join(refused),
                    "source": ev.source}
        return {"level": "probable", "text": "Administrative share(s) requested, outcome not observed: " + ", ".join(unknown or oc), "source": ev.source}
    if kind == "hidden_paths_found":
        h = ev.http_hits(src)
        return ({"level": "probable", "text": f"Fuzzing discovered {len(h)} reachable paths: " + ", ".join(u for u, _ in h[:6]), "source": ev.source}
                if h else {"level": "none", "text": "Fuzzing found nothing reachable", "source": ev.source})
    if kind == "ports_found":
        op = ev.open_ports(src)
        return {"level": "probable" if op else "none", "text": f"Scan identified live services on ports {op}" if op else "No live services identified", "source": ev.source}
    return {"level": "unknown", "text": "", "source": ev.source}


def _host_confirmed(src: str) -> str | None:
    if HOSTLOG.exists():
        for line in HOSTLOG.read_text(errors="replace").splitlines():
            if src in line and "Accepted password" in line:
                return line.strip()[:140]
    return None


# ------------------------------------------------------------------ test execution
def run_test(t: dict, conf_dir: Path, ev: Evidence, src: str) -> tuple[bool | None, str, str]:
    """-> (bad?, detail, evidence_kind). bad: True / False / None (unknown)."""
    k = t["kind"]
    if k == "evidence":
        fn = EVIDENCE_FNS[t["fn"]]
        args = {a: v for a, v in t.items() if a not in ("kind", "fn")}
        bad, detail = fn(ev, src, **args)
        return bad, detail, "network"
    text = _read(conf_dir, t["file"])
    if text is None:
        return None, f"{t['file']} not available", "config"
    if k == "section_exists":
        ex = section_exists(text, t["section"])
        return ex, f"[{t['section']}] {'is defined' if ex else 'is not defined'} in {t['file']}", "config"
    if k == "config_regex":
        found = bool(re.search(t["pattern"], text))
        bad = found if t.get("present_is_bad") else not found
        return bad, f"pattern /{t['pattern']}/ {'found' if found else 'not found'} in {t['file']}", "config"
    val = read_directive(text, t["key"], t.get("section"))
    shown = val if val is not None else t.get("default")
    if val is None and t.get("missing_is_bad"):
        return True, f"{t['key']} is not set in {t['file']}", "config"
    if shown is None:
        return None, f"{t['key']} not set", "config"
    if "bad_gt" in t:
        try:
            return float(shown) > t["bad_gt"], f"{t['key']} = {shown} in {t['file']}", "config"
        except ValueError:
            return None, f"{t['key']} = {shown}", "config"
    return str(shown).lower() in [b.lower() for b in t.get("bad", [])], f"{t['key']} = {shown}{' (default)' if val is None else ''} in {t['file']}", "config"


def evaluate(h: dict, conf_dir: Path, ev: Evidence, src: str) -> dict:
    results = [run_test(t, conf_dir, ev, src) for t in h["tests"]]
    known = [r for r in results if r[0] is not None]
    bad = [r for r in known if r[0]]
    if not known:
        status, conf = "unknown", "low"
    elif len(bad) == len(known):
        status = "confirmed"
        kinds = {r[2] for r in bad}
        conf = "high" if len(bad) >= 2 and len(kinds) >= 2 else "medium"
    elif bad:
        status, conf = "partial", "low"
    else:
        status, conf = "cleared", "high"
    return {"status": status, "confidence": conf, "evidence": [f"[{r[2]}] {r[1]}" for r in results]}


# ------------------------------------------------------------------ playbooks
def load_playbooks() -> dict:
    shared = yaml.safe_load((PLAYBOOKS / "_shared.yml").read_text(encoding="utf-8")) or {}
    out = {}
    for f in PLAYBOOKS.glob("*.yml"):
        if f.name.startswith("_"):
            continue
        pb = yaml.safe_load(f.read_text(encoding="utf-8"))
        pb["hypotheses"] = [shared[h["use"]] if "use" in h else h for h in pb["hypotheses"]]
        out[pb["class"]] = pb
    return out


# ------------------------------------------------------------------ fix application (on a copy)
def apply_ops(files: dict[str, str], ops: list[dict]) -> dict[str, str]:
    for op in ops:
        name = op["file"]
        txt = files.get(name, "")
        o = op["op"]
        if o == "write":
            txt = op["content"]
        elif o == "replace":
            txt = txt.replace(op["old"], op["new"])
        elif o == "prepend":
            txt = op["content"] + txt
        elif o == "set":
            txt = _set_directive(txt, op["key"], op["value"], op.get("section"))
        elif o == "remove_section":
            txt = re.sub(r"(?ms)^\[" + re.escape(op["section"]) + r"\]\s*\n.*?(?=^\[|\Z)", "", txt, flags=re.I)
        files[name] = txt
    return files


def _set_directive(txt: str, key: str, value: str, section: str | None) -> str:
    sep = " = " if "[" in txt else " "
    pat = re.compile(r"^(\s*)" + r"\s+".join(map(re.escape, key.split())) + r"\s*(?:=|\s)\s*.*$", re.I)
    lines, cur, done = txt.splitlines(), None, False
    for i, l in enumerate(lines):
        m = re.match(r"^\s*\[(.+)\]\s*$", l)
        if m:
            cur = m.group(1).lower()
            continue
        if (section is None or (cur or "") == section.lower()) and pat.match(l):
            lines[i] = f"{key}{sep}{value}"
            done = True
            break
    if not done:
        if section:
            idx = next((i for i, l in enumerate(lines) if l.strip().lower() == f"[{section.lower()}]"), None)
            if idx is not None:
                lines.insert(idx + 1, f"   {key}{sep}{value}")
            else:
                lines += [f"[{section}]", f"   {key}{sep}{value}"]
        else:
            lines.append(f"{key}{sep}{value}")
    return "\n".join(lines) + "\n"


def harden(causes: list[dict], conf_dir: Path = LAB_CONF) -> dict[str, str]:
    files = {p.name: p.read_text(encoding="utf-8") for p in conf_dir.iterdir() if p.is_file()}
    ops = [op for c in causes for op in (c.get("snippet") or [])]
    return apply_ops(files, ops)


# ------------------------------------------------------------------ main entry
def analyse(incident: dict, ev: Evidence, conf_dir: Path = LAB_CONF) -> dict:
    pbs = load_playbooks()
    mit = load_catalog()["mitigations"]
    src = incident["src"]
    stages, merged = [], {}
    for st in incident["stages"]:
        pb = pbs.get(st["class"])
        if not pb:
            continue
        imp = impact(pb["impact"]["fn"], ev, src)
        causes = []
        for h in pb["hypotheses"]:
            r = evaluate(h, conf_dir, ev, src)
            item = {"id": h["id"], "cause": h["cause"], "weight": h["weight"], "class": st["class"],
                    "mitigation": h["mitigation"], "mitigation_name": mit.get(h["mitigation"], ""),
                    "fix": h["fix"], "snippet": h.get("snippet") or [], **r}
            causes.append(item)
            if r["status"] == "confirmed":
                prev = merged.get(h["id"])
                if prev:
                    prev["classes"] = sorted(set(prev["classes"]) | {st["class"]})
                else:
                    merged[h["id"]] = {**item, "classes": [st["class"]]}
        stages.append({"class": st["class"], "title": st["title"], "impact": imp, "hypotheses": causes})
    ranked = sorted(merged.values(), key=lambda c: (-c["weight"], c["id"]))
    for n, c in enumerate(ranked, 1):
        c["rank"] = n
    return {"incident": incident["id"], "src": src, "evidence_source": ev.source,
            "stages": stages, "root_causes": ranked, "verification": verify(ranked, ev, src, conf_dir)}


def verify(causes: list[dict], ev: Evidence, src: str, conf_dir: Path = LAB_CONF) -> dict:
    """Apply the fixes to a copy of the configs and re-run every config test."""
    hardened = harden(causes, conf_dir)
    tmp = OUT / "hardened_conf"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    for n, t in hardened.items():
        (tmp / n).write_text(t, encoding="utf-8", newline=chr(10))
    pbs = load_playbooks()
    rows = []
    for c in causes:
        h = next(x for x in pbs[c["class"]]["hypotheses"] if x["id"] == c["id"])
        cfg = [t for t in h["tests"] if t["kind"] != "evidence"]
        if not cfg:
            rows.append({"id": c["id"], "result": "needs-live-reattack", "note": "only network evidence; re-run the attack against the patched lab (lab/verify)"})
            continue
        res = [run_test(t, tmp, ev, src)[0] for t in cfg]
        rows.append({"id": c["id"], "result": "cleared" if all(r is False for r in res) else "still-failing",
                     "note": "config test re-run on patched copy"})
    cleared = sum(1 for r in rows if r["result"] == "cleared")
    return {"rows": rows, "cleared": cleared, "total": len(rows)}


def write_fixpack(rca: dict, conf_dir: Path = LAB_CONF) -> Path:
    d = OUT / "fixpack" / rca["incident"]
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    hardened = harden(rca["root_causes"], conf_dir)
    diffs = []
    for name, new in hardened.items():
        old = (conf_dir / name).read_text(encoding="utf-8") if (conf_dir / name).exists() else ""
        if old != new:
            (d / name).write_text(new, encoding="utf-8", newline=chr(10))
            diffs += list(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{name}", f"b/{name}"))
    (d / "changes.diff").write_text("".join(diffs), encoding="utf-8", newline=chr(10))
    md = [f"# Fix pack for {rca['incident']} (source {rca['src']})", "",
          "Apply only to your own lab. Review the diff first.", ""]
    for c in rca["root_causes"]:
        md += [f"## {c['rank']}. {c['cause']}", f"*Confidence: {c['confidence']} | Mitigation {c['mitigation']} {c['mitigation_name']}*", "",
               f"- **Immediate:** {c['fix']['immediate']}", f"- **Short term:** {c['fix']['short_term']}", f"- **Long term:** {c['fix']['long_term']}", ""]
    (d / "FIXES.md").write_text("\n".join(md), encoding="utf-8", newline=chr(10))
    return d
