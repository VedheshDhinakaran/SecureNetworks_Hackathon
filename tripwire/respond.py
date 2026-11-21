"""Response engine: turn incidents into containment actions.

Safety first: DRY-RUN by default, never touches the management subnet, the victim itself or loopback,
and enforcement only ever targets the lab victim container.
"""
from __future__ import annotations

import ipaddress
import json
import subprocess

from .config import OUT, load_catalog

VICTIM_CONTAINER = "tripwire-victim"


def _protected(src: str) -> str | None:
    meta = load_catalog()["meta"]
    ip = ipaddress.ip_address(src)
    if ip in ipaddress.ip_network(meta["mgmt_subnet"]):
        return "inside the management subnet (allowlisted)"
    if str(ip) == meta["victim_ip"]:
        return "is the protected host itself"
    if ip.is_loopback:
        return "loopback address"
    return None


def plan(incidents: list[dict]) -> list[dict]:
    items = []
    for inc in incidents:
        src = inc["src"]
        why = _protected(src)
        classes = {s["class"] for s in inc["stages"]}
        acts = []
        if why:
            acts.append({"type": "skip", "rule": "", "reason": f"{src} is {why}"})
        else:
            acts.append({"type": "block", "rule": f"nft add rule inet filter input ip saddr {src} drop",
                         "reason": f"Contain {inc['severity']} incident {inc['id']} (risk {inc['risk']})"})
            if "ssh_bruteforce" in classes:
                acts.append({"type": "ratelimit", "rule": "nft add rule inet filter input tcp dport 22 ct state new limit rate over 6/minute drop",
                             "reason": "Throttle new SSH connections for everyone, not just this source"})
        items.append({"incident": inc["id"], "src": src, "mode": "dry-run", "actions": acts})
    return items


def write_plan(items: list[dict]) -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "response_plan.json").write_text(json.dumps(items, indent=1), encoding="utf-8")
    lines = ["# Tripwire response plan (DRY-RUN). Review, then apply only inside your own lab.", ""]
    for it in items:
        lines.append(f"# {it['incident']} source {it['src']}")
        for a in it["actions"]:
            lines.append(("# SKIPPED: " + a["reason"]) if a["type"] == "skip" else a["rule"])
        lines.append("")
    (OUT / "response.nft.txt").write_text("\n".join(lines), encoding="utf-8")


def enforce(items: list[dict]) -> list[dict]:
    """Apply block rules inside the lab victim container. Explicit opt-in (--enforce)."""
    results = []
    for it in items:
        for a in it["actions"]:
            if a["type"] != "block":
                continue
            r = subprocess.run(["docker", "exec", VICTIM_CONTAINER, "sh", "-c", a["rule"]], capture_output=True, text=True, timeout=30)
            results.append({"incident": it["incident"], "rule": a["rule"], "ok": r.returncode == 0, "output": (r.stderr or r.stdout).strip()[:200]})
    return results
