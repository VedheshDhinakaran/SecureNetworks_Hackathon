"""Evidence store: facts about what an attacker actually did, used by root cause analysis.

Preferred source is Zeek (conn.log, http.log, smb_mapping.log). When Zeek is not available the
same structure is derived directly from the PCAP, so the platform degrades gracefully and says
which source it used.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

HIT_STATUS = {200, 301, 302, 401, 403}
NOISE_PATHS = {"/", "/favicon.ico", "/robots.txt"}


class Evidence:
    def __init__(self, source: str = "none"):
        self.source = source
        self.conns: dict[str, list] = defaultdict(list)   # src -> [(ts, dst, dport, answered, dur, nbytes, state)]  state: open|rejected|filtered|None
        self.smb: dict[str, list] = defaultdict(list)     # src -> [(ts, path, outcome)]  outcome: granted|denied|error|None
        self.http: dict[str, list] = defaultdict(list)    # src -> [(ts, uri, status, ua)]
        self.ssh_auth: dict[str, list] = defaultdict(list)  # src -> [(ts, success True|False|None, inferred_attempts)]  (Zeek ssh.log)

    # -- ingestion (used for files and for the live tailer) --------------------------
    def add_conn(self, ts, src, dst, dport, answered, dur=0.0, nbytes=0, state=None):
        self.conns[src].append((ts, dst, int(dport), bool(answered), float(dur or 0), int(nbytes or 0), state))

    def add_smb(self, ts, src, path, outcome=None):
        self.smb[src].append((ts, path, outcome))

    def add_http(self, ts, src, uri, status, ua=""):
        self.http[src].append((ts, uri, int(status or 0), ua))

    # -- queries -------------------------------------------------------------------
    def probed_ports(self, src) -> list[int]:
        return sorted({c[2] for c in self.conns.get(src, [])})

    def open_ports(self, src) -> list[int]:
        return sorted({c[2] for c in self.conns.get(src, []) if c[3]})

    def probe_summary(self, src) -> dict:
        """What a scan found: ports that answered (open), were refused (rejected) or never answered (filtered)."""
        st: dict[int, str] = {}
        for c in self.conns.get(src, []):
            port, state = c[2], (c[6] if len(c) > 6 else None)
            if c[3]:
                st[port] = "open"
            elif port not in st:
                st[port] = state or "unknown"
        by = lambda k: sorted(p for p, v in st.items() if v == k)
        return {"probed": len(st), "open": by("open"), "rejected": by("rejected"), "filtered": by("filtered")}

    def smb_admin_paths(self, src) -> list[str]:
        out = []
        for _, p, _o in self.smb.get(src, []):
            tail = p.rsplit("\\", 1)[-1].upper()
            if tail in ("ADMIN$", "C$", "D$", "E$") and p not in out:
                out.append(p)
        return out

    def smb_admin_outcomes(self, src) -> dict[str, str | None]:
        """path -> best known outcome (granted beats denied beats error beats unknown)."""
        rank = {"granted": 3, "denied": 2, "error": 1, None: 0, "unknown": 0}
        best: dict[str, str | None] = {}
        for _, p, o in self.smb.get(src, []):
            tail = p.rsplit("\\", 1)[-1].upper()
            if tail in ("ADMIN$", "C$", "D$", "E$") and rank.get(o, 0) >= rank.get(best.get(p), -1):
                best[p] = o
        return best

    def http_hits(self, src) -> list[tuple[str, int]]:
        seen: dict[str, int] = {}
        for _, uri, st, _ua in self.http.get(src, []):
            if st in HIT_STATUS and uri not in NOISE_PATHS:
                seen[uri] = st
        return sorted(seen.items())

    def add_ssh_auth(self, ts, src, success, attempts):
        self.ssh_auth[src].append((ts, success, int(attempts or 0)))

    def ssh_attempts(self, src) -> int:
        """Password attempts: Zeek's inferred count in failed sessions when we have it, else connections to port 22."""
        s = self.ssh_auth_summary(src)
        if s and (s["failed_sessions"] or s["successful_sessions"]):     # Zeek actually inferred an outcome
            return s["failed_attempts"]
        return sum(1 for c in self.conns.get(src, []) if c[2] == 22)

    def ssh_auth_summary(self, src) -> dict | None:
        """Zeek's INFERRED authentication outcomes (encrypted SSH: an estimate from packet sizes, not ground truth)."""
        rows = sorted(self.ssh_auth.get(src, []))
        if not rows:
            return None
        failed = [r for r in rows if r[1] is False]
        ok = [r for r in rows if r[1] is True]
        return {"sessions": len(rows), "failed_sessions": len(failed), "failed_attempts": sum(r[2] for r in failed),
                "successful_sessions": len(ok), "unknown_sessions": sum(1 for r in rows if r[1] is None),
                "success_attempts": ok[0][2] if ok else 0, "success_ts": ok[0][0] if ok else None}

    def ssh_possible_success(self, src) -> dict | None:
        """Heuristic only: encrypted SSH hides auth results. A long, data-rich session that follows a
        run of short failed ones is how a successful guess looks on the wire."""
        sm = self.ssh_auth_summary(src)
        if sm and sm["successful_sessions"] and sm["failed_attempts"] + sm["success_attempts"] - 1 >= 3:
            return {"inferred": True, "failed_attempts": sm["failed_attempts"], "failed_sessions": sm["failed_sessions"],
                    "success_attempts": sm["success_attempts"], "ts": sm["success_ts"]}
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
        a = (s, d, dp) in answered
        ev.add_conn(ts, s, d, dp, a, state="open" if a else ("rejected" if (s, d, dp) in facts.rst else "filtered"))
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
    from .native import smb_outcome
    for ts, s, path, sport, mid in facts.smb:
        ev.add_smb(ts, s, path, smb_outcome(facts.smb_out.get((s, sport, mid))))
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
        cs = r.get("conn_state")
        ev.add_conn(r["ts"], r["id.orig_h"], r["id.resp_h"], r["id.resp_p"], answered, r.get("duration"), nbytes,
                    state="open" if answered else ("rejected" if cs == "REJ" else ("filtered" if cs in ("S0", "SH") else None)))
    for r in _jsonl(d / "http.log"):
        ev.add_http(r["ts"], r["id.orig_h"], r.get("uri", ""), r.get("status_code", 0), r.get("user_agent", ""))
    for r in _jsonl(d / "ssh.log"):
        if r.get("id.resp_p") == 22 or r.get("id.resp_p") is None:
            ev.add_ssh_auth(r["ts"], r["id.orig_h"], r.get("auth_success"), r.get("auth_attempts", 0))
    for r in _jsonl(d / "smb_mapping.log"):
        ev.add_smb(r["ts"], r["id.orig_h"], r.get("path", ""), "granted")     # smb_mapping.log records successful mappings only
    # attempts that were refused never reach smb_mapping.log: recover them from our outcome notices
    for r in _jsonl(d / "notice.log"):
        if r.get("note") == "Tripwire::SMB_Admin_Share_Result":
            m = re.search(r"administrative share (.+?) result=(\w+)", r.get("msg", ""))
            if m:
                ev.add_smb(r["ts"], r.get("src", ""), m.group(1),
                           {"ACCESS_GRANTED": "granted", "ACCESS_DENIED": "denied"}.get(m.group(2), "error"))
    return ev
