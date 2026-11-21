"""Evidence store: facts about what an attacker actually did, used by root cause analysis.

Preferred source is Zeek (conn.log, http.log, smb_mapping.log). When Zeek is not available the
same structure is derived directly from the PCAP, so the platform degrades gracefully and says
which source it used.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

HIT_STATUS = {200, 301, 302, 401, 403}
NOISE_PATHS = {"/", "/favicon.ico", "/robots.txt"}


class Evidence:
    def __init__(self, source: str = "none"):
        self.source = source
        self.conns: dict[str, list] = defaultdict(list)   # src -> [(ts, dst, dport, answered, dur, nbytes)]
        self.smb: dict[str, list] = defaultdict(list)     # src -> [(ts, path)]
        self.http: dict[str, list] = defaultdict(list)    # src -> [(ts, uri, status, ua)]

    # -- ingestion (used for files and for the live tailer) --------------------------
    def add_conn(self, ts, src, dst, dport, answered, dur=0.0, nbytes=0):
        self.conns[src].append((ts, dst, int(dport), bool(answered), float(dur or 0), int(nbytes or 0)))

    def add_smb(self, ts, src, path):
        self.smb[src].append((ts, path))

    def add_http(self, ts, src, uri, status, ua=""):
        self.http[src].append((ts, uri, int(status or 0), ua))

    # -- queries -------------------------------------------------------------------
    def probed_ports(self, src) -> list[int]:
        return sorted({c[2] for c in self.conns.get(src, [])})

    def open_ports(self, src) -> list[int]:
        return sorted({c[2] for c in self.conns.get(src, []) if c[3]})

    def smb_admin_paths(self, src) -> list[str]:
        out = []
        for _, p in self.smb.get(src, []):
            tail = p.rsplit("\\", 1)[-1].upper()
            if tail in ("ADMIN$", "C$", "D$", "E$") and p not in out:
                out.append(p)
        return out

    def http_hits(self, src) -> list[tuple[str, int]]:
        seen: dict[str, int] = {}
        for _, uri, st, _ua in self.http.get(src, []):
            if st in HIT_STATUS and uri not in NOISE_PATHS:
                seen[uri] = st
        return sorted(seen.items())

    def ssh_attempts(self, src) -> int:
        return sum(1 for c in self.conns.get(src, []) if c[2] == 22)

    def ssh_possible_success(self, src) -> dict | None:
        """Heuristic only: encrypted SSH hides auth results. A long, data-rich session that follows a
        run of short failed ones is how a successful guess looks on the wire."""
        flows = sorted((c for c in self.conns.get(src, []) if c[2] == 22), key=lambda c: c[0])
        short = sum(1 for c in flows if c[4] < 3)
        for c in flows:
            if c[4] >= 10 and c[5] >= 3000 and short >= 3:
                return {"ts": c[0], "duration_s": round(c[4], 1), "bytes": c[5], "failed_before": short}
        return None


def from_native(facts) -> Evidence:
    ev = Evidence("pcap (native parser)")
    answered = {(cl, sv, sp) for _, cl, sv, sp in facts.synack}
    seen = set()
    for ts, s, d, dp in facts.syn:
        ev.add_conn(ts, s, d, dp, (s, d, dp) in answered)
        seen.add((s, d, dp))
    # SSH flows carry duration and volume
    for (client, _sport), (t0, t1, nbytes) in facts.ssh_flows.items():
        # replace the bare SYN record of this flow with a richer one
        ev.conns[client] = [c for c in ev.conns[client] if not (c[2] == 22 and abs(c[0] - t0) < 0.01)]
        ev.add_conn(t0, client, "", 22, True, t1 - t0, nbytes)
    reqs = defaultdict(list)
    for ts, cl, uri, ua in facts.http_req:
        reqs[cl].append((ts, uri, ua))
    resps = defaultdict(list)
    for ts, cl, code in facts.http_resp:
        resps[cl].append(code)
    for cl, lst in reqs.items():
        for i, (ts, uri, ua) in enumerate(sorted(lst)):
            code = resps[cl][i] if i < len(resps[cl]) else 0
            ev.add_http(ts, cl, uri, code, ua)
    for ts, s, path in facts.smb:
        ev.add_smb(ts, s, path)
    return ev


def _jsonl(path: Path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def from_zeek(d: Path) -> Evidence | None:
    d = Path(d)
    if not (d / "conn.log").exists():
        return None
    ev = Evidence("zeek logs")
    for r in _jsonl(d / "conn.log"):
        hist = r.get("history", "") or ""
        answered = "h" in hist or r.get("conn_state") in ("SF", "S1", "S2", "S3")
        nbytes = (r.get("orig_bytes") or 0) + (r.get("resp_bytes") or 0)
        ev.add_conn(r["ts"], r["id.orig_h"], r["id.resp_h"], r["id.resp_p"], answered, r.get("duration"), nbytes)
    for r in _jsonl(d / "http.log"):
        ev.add_http(r["ts"], r["id.orig_h"], r.get("uri", ""), r.get("status_code", 0), r.get("user_agent", ""))
    for r in _jsonl(d / "smb_mapping.log"):
        ev.add_smb(r["ts"], r["id.orig_h"], r.get("path", ""))
    return ev
