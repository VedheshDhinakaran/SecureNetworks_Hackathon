"""Native Python detector plugin + packet feature extraction.

Two jobs:
  1. an independent third detector that needs no Docker (statistical, same two layers)
  2. the fast feature engine behind the threshold sweep: for each PCAP it reports the
     peak per-source metric (e.g. max SYNs in 5 s), so any threshold can be evaluated
     instantly and then verified against the real engines.
"""
from __future__ import annotations

import ipaddress
import re
import struct
from bisect import bisect_left
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from scapy.config import conf

conf.verb = 0
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

from .config import load_catalog  # noqa: E402

UA_RE = re.compile(r"(fuzz faceless|gobuster|sqlmap|nikto|wfuzz|dirbuster)", re.I)
ADMIN_SHARE_RE = re.compile(r"\\(c|d|e|admin)\$$", re.I)
SMB2_MAGIC = bytes([0xFE]) + b"SMB"


def smb_outcome(status) -> str:
    """NTSTATUS of a tree-connect reply -> granted | denied | error | unknown."""
    if status is None:
        return "unknown"
    return {0: "granted", 0xC0000022: "denied"}.get(status, "error")


@dataclass
class Facts:
    """Everything the detectors and the evidence builder need from one PCAP."""
    name: str = ""
    t0: float = 0.0
    t1: float = 0.0
    syn: list = field(default_factory=list)        # (ts, src, dst, dport)
    synack: list = field(default_factory=list)     # (ts, client, server, sport)
    http_req: list = field(default_factory=list)   # (ts, client, path, ua)
    http_resp: list = field(default_factory=list)  # (ts, client, code)
    smb: list = field(default_factory=list)        # (ts, src, share_path, sport, message_id)
    smb_out: dict = field(default_factory=dict)    # (client, sport, message_id) -> NTSTATUS of the tree-connect reply
    ssh_flows: dict = field(default_factory=dict)  # (src, sport) -> [first, last, bytes]


_CACHE: dict[str, Facts] = {}


def parse_pcap(path: str | Path) -> Facts:
    path = str(path)
    if path in _CACHE:
        return _CACHE[path]
    f = Facts(name=Path(path).stem)
    first = last = None
    with PcapReader(path) as rd:
        for pkt in rd:
            if IP not in pkt or TCP not in pkt:
                continue
            ts = float(pkt.time)
            first = ts if first is None else first
            last = ts
            ip, tcp = pkt[IP], pkt[TCP]
            flags = int(tcp.flags)
            payload = bytes(tcp.payload)
            if flags & 0x02 and not flags & 0x10:
                f.syn.append((ts, ip.src, ip.dst, tcp.dport))
            elif flags & 0x12 == 0x12:
                f.synack.append((ts, ip.dst, ip.src, tcp.sport))
            if tcp.dport == 22 or tcp.sport == 22:
                client, sport = (ip.src, tcp.sport) if tcp.dport == 22 else (ip.dst, tcp.dport)
                fl = f.ssh_flows.setdefault((client, sport), [ts, ts, 0])
                fl[1] = ts
                fl[2] += len(payload)
            if not payload:
                continue
            if payload.startswith(b"GET "):
                line, _, rest = payload.partition(b"\r\n")
                ua = ""
                m = re.search(rb"User-Agent: ([^\r\n]*)", rest, re.I)
                if m:
                    ua = m.group(1).decode("latin1")
                f.http_req.append((ts, ip.src, line.split(b" ")[1].decode("latin1"), ua))
            elif payload.startswith(b"HTTP/1."):
                try:
                    code = int(payload[9:12])
                    f.http_resp.append((ts, ip.dst, code))
                except ValueError:
                    pass
            elif (tcp.dport == 445 or tcp.sport == 445) and len(payload) > 70 and payload[4:8] == SMB2_MAGIC:
                status = struct.unpack_from("<I", payload, 4 + 8)[0]
                cmd = struct.unpack_from("<H", payload, 4 + 12)[0]
                flg = struct.unpack_from("<I", payload, 4 + 16)[0]
                mid = struct.unpack_from("<Q", payload, 4 + 24)[0]
                if cmd == 3 and not flg & 1 and tcp.dport == 445:           # tree-connect request
                    off, ln = struct.unpack_from("<HH", payload, 4 + 64 + 4)
                    share = payload[4 + off:4 + off + ln].decode("utf-16-le", "replace")
                    f.smb.append((ts, ip.src, share, tcp.sport, mid))
                elif cmd == 3 and flg & 1 and tcp.sport == 445 and status != 0x103:   # final reply (0x103 = pending)
                    f.smb_out[(ip.dst, tcp.dport, mid)] = status
    f.t0, f.t1 = first or 0.0, last or 0.0
    _CACHE[path] = f
    return f


# ------------------------------------------------------------ window maths
def window_cross(times: list[float], count: int, window: float):
    """Timestamp at which `count` events first fall within `window` seconds, else None."""
    ts = sorted(times)
    for i in range(count - 1, len(ts)):
        if ts[i] - ts[i - count + 1] <= window:
            return ts[i]
    return None


def window_max(times: list[float], window: float) -> int:
    ts = sorted(times)
    best = 0
    for i, t in enumerate(ts):
        j = bisect_left(ts, t - window)
        best = max(best, i - j + 1)
    return best


def unique_max(items: list[tuple[float, object]], window: float) -> int:
    items = sorted(items, key=lambda x: x[0])
    dq: deque = deque()
    cnt: dict = defaultdict(int)
    best = 0
    for t, k in items:
        dq.append((t, k))
        cnt[k] += 1
        while dq and dq[0][0] < t - window:
            _, kk = dq.popleft()
            cnt[kk] -= 1
            if cnt[kk] == 0:
                del cnt[kk]
        best = max(best, len(cnt))
    return best


def unique_cross(items: list[tuple[float, object]], count: int, window: float):
    items = sorted(items, key=lambda x: x[0])
    dq: deque = deque()
    cnt: dict = defaultdict(int)
    for t, k in items:
        dq.append((t, k))
        cnt[k] += 1
        while dq and dq[0][0] < t - window:
            _, kk = dq.popleft()
            cnt[kk] -= 1
            if cnt[kk] == 0:
                del cnt[kk]
        if len(cnt) >= count:
            return t
    return None


# ------------------------------------------------------------ features (sweep)
def _in_home(ip: str, home_prefix: str) -> bool:
    return ip.startswith(home_prefix)


def features(f: Facts, home_prefix: str = "10.0.0.") -> dict[str, dict[str, int]]:
    """Peak per-source metric per class and layer. Used for the threshold sweep."""
    cat = load_catalog()["classes"]
    out: dict[str, dict[str, int]] = {c: {"L1": 0, "L2": 0} for c in cat}
    by_src = defaultdict(list)
    ports = defaultdict(list)
    ssh = defaultdict(list)
    for ts, s, d, dp in f.syn:
        if not _in_home(d, home_prefix):
            continue
        by_src[s].append(ts)
        ports[s].append((ts, dp))
        if dp == 22:
            ssh[s].append(ts)
    w = cat["scan"]
    out["scan"]["L1"] = max((window_max(v, w["l1"]["window"]) for v in by_src.values()), default=0)
    out["scan"]["L2"] = max((unique_max(v, w["l2"]["window"]) for v in ports.values()), default=0)
    w = cat["ssh_bruteforce"]
    out["ssh_bruteforce"]["L1"] = max((window_max(v, w["l1"]["window"]) for v in ssh.values()), default=0)
    out["ssh_bruteforce"]["L2"] = max((window_max(v, w["l2"]["window"]) for v in ssh.values()), default=0)
    miss = defaultdict(list)
    for ts, cl, code in f.http_resp:
        if code == 404:
            miss[cl].append(ts)
    w = cat["web_fuzz"]
    out["web_fuzz"]["L1"] = max((window_max(v, w["l1"]["window"]) for v in miss.values()), default=0)
    out["web_fuzz"]["L2"] = max((window_max(v, w["l2"]["window"]) for v in miss.values()), default=0)
    out["smb_admin"]["L1"] = out["smb_admin"]["L2"] = sum(1 for t in f.smb if ADMIN_SHARE_RE.search(t[2]))
    return out


# ------------------------------------------------------------ detector
def _ev(ts, layer, cls, cat, src, dst, dport, rule, name, detail, pcap):
    c = cat[cls]
    return {"ts": ts, "sensor": "native", "layer": layer, "class": cls, "rule": rule, "name": name,
            "src": src, "dst": dst, "dport": dport, "technique": c["technique"], "tactic": c["tactic"],
            "severity": c["severity"], "detail": detail, "pcap": pcap}


def detect(f: Facts, th: dict | None = None, home_prefix: str = "10.0.0.") -> list[dict]:
    cat = load_catalog()["classes"]
    th = th or {}
    victim = load_catalog()["meta"]["victim_ip"]
    ev: list[dict] = []
    by_src, ports, ssh = defaultdict(list), defaultdict(list), defaultdict(list)
    for ts, s, d, dp in f.syn:
        if _in_home(d, home_prefix):
            by_src[s].append(ts)
            ports[s].append((ts, dp))
            if dp == 22:
                ssh[s].append(ts)

    def p(cls, layer):
        base = cat[cls]["l1" if layer == "L1" else "l2"]
        return th.get(f"{cls}.{layer}.count", base["count"]), base["window"]

    for src, v in by_src.items():
        n, w = p("scan", "L1")
        t = window_cross(v, n, w)
        if t is not None:
            ev.append(_ev(t, "L1", "scan", cat, src, victim, 0, "NATIVE-SCAN-L1", "SYN sweep", f"{n}+ SYNs in {w}s", f.name))
    for src, v in ports.items():
        n, w = p("scan", "L2")
        t = unique_cross(v, n, w)
        if t is not None:
            ev.append(_ev(t, "L2", "scan", cat, src, victim, 0, "NATIVE-SCAN-L2", "Many distinct ports", f"{n}+ ports in {w}s", f.name))
    for src, v in ssh.items():
        for layer in ("L1", "L2"):
            n, w = p("ssh_bruteforce", layer)
            t = window_cross(v, n, w)
            if t is not None:
                ev.append(_ev(t, layer, "ssh_bruteforce", cat, src, victim, 22, f"NATIVE-SSH-{layer}", "SSH connection rate", f"{n}+ SSH conns in {w}s", f.name))
    miss = defaultdict(list)
    for ts, cl, code in f.http_resp:
        if code == 404:
            miss[cl].append(ts)
    for src, v in miss.items():
        for layer in ("L1", "L2"):
            n, w = p("web_fuzz", layer)
            t = window_cross(v, n, w)
            if t is not None:
                ev.append(_ev(t, layer, "web_fuzz", cat, src, victim, 80, f"NATIVE-FUZZ-{layer}", "404 burst", f"{n}+ 404s in {w}s", f.name))
    seen_ua = set()
    for ts, src, _path, ua in f.http_req:
        if UA_RE.search(ua) and src not in seen_ua:
            seen_ua.add(src)
            ev.append(_ev(ts, "L1", "web_fuzz", cat, src, victim, 80, "NATIVE-FUZZ-UA", "Fuzzer user agent", ua, f.name))
    seen = set()
    mgmt = ipaddress.ip_network(load_catalog()["meta"]["mgmt_subnet"])
    for ts, src, share, sport, mid in f.smb:
        if ipaddress.ip_address(src) in mgmt:               # designated admin hosts are allowlisted by policy
            continue
        if ADMIN_SHARE_RE.search(share) and (src, share.lower()) not in seen:
            seen.add((src, share.lower()))
            e = _ev(ts, "L1", "smb_admin", cat, src, victim, 445, "NATIVE-SMB-ADMIN", "Admin share tree-connect", share, f.name)
            e["outcome"] = smb_outcome(f.smb_out.get((src, sport, mid)))
            e["detail"] = f"{share} -> {e['outcome']}"
            ev.append(e)
    return sorted(ev, key=lambda e: e["ts"])
