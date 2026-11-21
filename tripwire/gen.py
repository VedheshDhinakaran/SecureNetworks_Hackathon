"""Deterministic, labelled PCAP generator (scapy).

Why synthetic traffic as well as a real lab?
  * every PCAP is reproducible from a seed, so judges can re-run the exact test
  * ground truth is known by construction (who attacked, when, what class)
  * we can dial attack speed to measure the detection envelope (robustness grid)
The real Docker lab (lab/) produces authentic captures of the same four attacks.
"""
from __future__ import annotations

import json
import struct
from datetime import datetime, timezone

from scapy.config import conf

conf.verb = 0
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

import random  # noqa: E402

from .config import MANIFEST, PCAPS, ensure_dirs  # noqa: E402

T0 = datetime(2026, 11, 21, 9, 0, 0, tzinfo=timezone.utc).timestamp()
VICTIM = "10.0.0.10"
FFUF_UA = "Fuzz Faceless"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
SSH_SERVER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"


def mac(ip: str) -> str:
    a = [int(x) for x in ip.split(".")]
    return "02:00:%02x:%02x:%02x:%02x" % tuple(a)


class Cap:
    """A growing list of packets with explicit timestamps."""

    def __init__(self, seed: int):
        self.pk: list = []
        self.rng = random.Random(seed)
        self._sp = 40000

    def sport(self) -> int:
        self._sp += 1
        if self._sp > 60000:
            self._sp = 40001
        return self._sp

    def add(self, t, src, dst, sport, dport, flags, seq, ack, payload=b""):
        p = (Ether(src=mac(src), dst=mac(dst)) /
             IP(src=src, dst=dst, ttl=64) /
             TCP(sport=sport, dport=dport, flags=flags, seq=seq & 0xFFFFFFFF,
                 ack=ack & 0xFFFFFFFF, window=64240))
        if payload:
            p = p / Raw(payload)
        p.time = float(t)
        self.pk.append(p)

    def write(self, path) -> None:
        self.pk.sort(key=lambda p: float(p.time))
        wrpcap(str(path), self.pk)

    def span(self) -> tuple[float, float]:
        ts = [float(p.time) for p in self.pk]
        return min(ts), max(ts)


class Conn:
    """A TCP connection with correct sequence/ack numbers."""

    def __init__(self, cap: Cap, t: float, c: str, s: str, dport: int, dt: float = 0.0008):
        self.cap, self.t, self.c, self.s, self.dport, self.dt = cap, t, c, s, dport, dt
        self.sport = cap.sport()
        self.cseq = cap.rng.randint(1000, 2 ** 31)
        self.sseq = cap.rng.randint(1000, 2 ** 31)

    def at(self, t: float) -> "Conn":
        self.t = max(self.t, t)
        return self

    def _send(self, d: str, flags: str, payload: bytes = b"", noack: bool = False) -> None:
        if d == "c":
            src, dst, sp, dp, seq, ack = self.c, self.s, self.sport, self.dport, self.cseq, self.sseq
        else:
            src, dst, sp, dp, seq, ack = self.s, self.c, self.dport, self.sport, self.sseq, self.cseq
        self.cap.add(self.t, src, dst, sp, dp, flags, seq, 0 if noack else ack, payload)
        adv = len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        if d == "c":
            self.cseq += adv
        else:
            self.sseq += adv
        self.t += self.dt

    def open(self) -> "Conn":
        self._send("c", "S", noack=True)
        self._send("s", "SA")
        self._send("c", "A")
        return self

    def _data(self, d: str, data: bytes) -> None:
        other = "s" if d == "c" else "c"
        for i in range(0, len(data), 1400):
            self._send(d, "PA", data[i:i + 1400])
            self._send(other, "A")

    def data_c(self, data: bytes) -> None:
        self._data("c", data)

    def data_s(self, data: bytes) -> None:
        self._data("s", data)

    def close(self) -> None:
        self._send("c", "FA")
        self._send("s", "FA")
        self._send("c", "A")


def probe(cap: Cap, t: float, c: str, s: str, dport: int, state: str) -> None:
    """One nmap-style SYN probe. state: open | closed | filtered."""
    sp = cap.sport()
    seq = cap.rng.randint(1000, 2 ** 31)
    cap.add(t, c, s, sp, dport, "S", seq, 0)
    if state == "open":
        sseq = cap.rng.randint(1000, 2 ** 31)
        cap.add(t + 0.0004, s, c, dport, sp, "SA", sseq, seq + 1)
        cap.add(t + 0.0008, c, s, sp, dport, "R", seq + 1, 0)
    elif state == "closed":
        cap.add(t + 0.0004, s, c, dport, sp, "RA", 0, seq + 1)


# ---------------------------------------------------------------- protocols
def ssh_session(cap: Cap, t: float, c: str, client_banner: bytes, long_for: float = 0.0) -> float:
    """SSH connection: banner exchange, key exchange, then fail (short) or a long interactive session."""
    cn = Conn(cap, t, c, VICTIM, 22).open()
    cn.data_s(SSH_SERVER)
    cn.data_c(client_banner)
    cn.data_c(cap.rng.randbytes(1180))
    cn.data_s(cap.rng.randbytes(1090))
    cn.data_c(cap.rng.randbytes(310))
    cn.data_s(cap.rng.randbytes(880))
    if long_for <= 0:
        cn.at(cn.t + 0.05)
        cn.data_c(cap.rng.randbytes(96))     # one password attempt
        cn.data_s(cap.rng.randbytes(80))     # auth failure
        cn.close()
        return cn.t
    end = cn.t + long_for
    while cn.t < end:                        # interactive session: keystrokes and output
        cn.at(cn.t + cap.rng.uniform(0.4, 2.0))
        cn.data_c(cap.rng.randbytes(cap.rng.randint(36, 80)))
        cn.data_s(cap.rng.randbytes(cap.rng.randint(80, 600)))
    cn.close()
    return cn.t


REASON = {200: "OK", 301: "Moved Permanently", 304: "Not Modified", 403: "Forbidden", 404: "Not Found"}


def http_get(cn: Conn, path: str, ua: str, code: int, body_len: int = 0) -> None:
    req = f"GET {path} HTTP/1.1\r\nHost: {VICTIM}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n"
    if code == 404 and not body_len:
        body_len = 40
    body = (b"<html>" + b"x" * max(0, body_len - 13) + b"</html>") if body_len else b""
    resp = (f"HTTP/1.1 {code} {REASON[code]}\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode() + body
    cn.data_c(req.encode())
    cn.data_s(resp)


def nb(msg: bytes) -> bytes:
    return b"\x00" + len(msg).to_bytes(3, "big") + msg


def smb2_hdr(cmd: int, mid: int, flags: int = 0, tree: int = 0, sess: int = 0) -> bytes:
    return b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, cmd, 1, flags, 0, mid, 0, tree, sess) + b"\x00" * 16


def smb_session(cap: Cap, t: float, c: str, shares: list[str], gap: float = 0.4) -> float:
    """SMB2 negotiate + session setup + one tree-connect per share (UNC paths in UTF-16LE)."""
    cn = Conn(cap, t, c, VICTIM, 445).open()
    guid = cap.rng.randbytes(16)
    sess = 0x0000_1122_3344_5566
    cn.data_c(nb(smb2_hdr(0, 0) + struct.pack("<HHHHI", 36, 1, 1, 0, 0) + guid + b"\x00" * 8 + struct.pack("<H", 0x0210)))
    cn.data_s(nb(smb2_hdr(0, 0, 1) + struct.pack("<HHHH", 65, 1, 0x0210, 0) + guid +
                 struct.pack("<IIII", 0, 65536, 65536, 65536) + struct.pack("<QQ", 0, 0) + struct.pack("<HHI", 128, 0, 0)))
    blob = b"NTLMSSP\x00" + b"\x01\x00\x00\x00" + b"\x00" * 8
    cn.data_c(nb(smb2_hdr(1, 1) + struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(blob), 0) + blob))
    cn.data_s(nb(smb2_hdr(1, 1, 1, sess=sess) + struct.pack("<HHHH", 9, 0, 72, 0)))
    for i, share in enumerate(shares):
        path = f"\\\\{VICTIM}\\{share}".encode("utf-16-le")
        cn.at(cn.t + gap)
        cn.data_c(nb(smb2_hdr(3, 2 + i, 0, 0, sess) + struct.pack("<HHHH", 9, 0, 72, len(path)) + path))
        cn.data_s(nb(smb2_hdr(3, 2 + i, 1, tree=i + 1, sess=sess) + struct.pack("<HBBIII", 16, 1, 0, 0x30, 0, 0x1F01FF)))
    cn.close()
    return cn.t


# ---------------------------------------------------------------- scenarios
WORDS = ("admin login backup test config old dev api v1 v2 uploads images css js static assets docs "
         "private secret internal tmp temp data db sql dump bak www web site staging prod portal manager "
         "console panel cgi-bin server-status phpinfo wp-admin wp-login dashboard users user account "
         "register reset password health status metrics debug trace download files share public").split()
HITS = {"admin": 301, "backup": 200, ".git/HEAD": 200, "robots.txt": 200}


def sc_scan(cap, t, ip, ports=1000, pps=500.0):
    plist = list(range(1, ports + 1))
    cap.rng.shuffle(plist)
    openp = {22, 80, 139, 445}
    for i, p in enumerate(plist):
        probe(cap, t + i / pps, ip, VICTIM, p, "open" if p in openp else "closed")
    return t + ports / pps


def sc_ssh(cap, t, ip, n=60, interval=0.5, success=True, banner=b"SSH-2.0-libssh_0.10.5\r\n"):
    end = t
    for i in range(n):
        ts = t + i * interval
        last = success and i == n - 1
        end = ssh_session(cap, ts, ip, banner, long_for=35.0 if last else 0.0)
    return end


def sc_smb(cap, t, ip, shares, spacing=3.0):
    end = t
    for i, sh in enumerate(shares):
        end = smb_session(cap, t + i * spacing, ip, [sh])
    return end


def sc_fuzz(cap, t, ip, n=300, rps=40.0, ua=FFUF_UA, conns=5):
    cs = [Conn(cap, t, ip, VICTIM, 80).open() for _ in range(conns)]
    words = (WORDS * (n // len(WORDS) + 2))[:n]
    words[len(words) // 3] = "admin"
    words[len(words) // 2] = "backup"
    words[(2 * len(words)) // 3] = ".git/HEAD"
    for i, w in enumerate(words):
        cn = cs[i % conns].at(t + i / rps)
        code = HITS.get(w, 404)
        http_get(cn, "/" + w, ua, code, 300 if code == 200 else 0)
    end = max(c.t for c in cs)
    for c in cs:
        c.close()
    return end


def sc_browse(cap, t, ip, pages=1, ua=CHROME_UA, favicon=False):
    cn = Conn(cap, t, ip, VICTIM, 80).open()
    for _ in range(pages):
        cn.at(cn.t + cap.rng.uniform(0.2, 1.0))
        http_get(cn, "/", ua, 200, 1100)
        for res, ln in (("/static/app.css", 640), ("/static/app.js", 1900), ("/img/logo.png", 800)):
            cn.at(cn.t + cap.rng.uniform(0.02, 0.2))
            http_get(cn, res, ua, 200 if cap.rng.random() > 0.3 else 304, ln)
        if favicon:
            http_get(cn, "/favicon.ico", ua, 404)
            favicon = False
    cn.close()
    return cn.t


# ---------------------------------------------------------------- datasets
def _entry(cap, name, kind, expect, attackers, desc, **extra):
    lo, hi = cap.span()
    e = {"name": name, "file": f"{name}.pcap", "kind": kind, "expect": expect,
         "attacker_ips": attackers, "attack_start": extra.pop("attack_start", lo),
         "start": lo, "end": hi, "duration": round(hi - lo, 1), "packets": len(cap.pk), "desc": desc}
    e.update(extra)
    return e


def _save(cap, name, kind, expect, attackers, desc, **extra):
    cap.write(PCAPS / f"{name}.pcap")
    return _entry(cap, name, kind, expect, attackers, desc, **extra)


def build_dataset(seed: int = 7) -> list[dict]:
    ensure_dirs()
    m: list[dict] = []

    def cap(i):
        return Cap(seed * 100 + i)

    # -- core attacks ----------------------------------------------------------------
    c = cap(1); sc_scan(c, T0, "10.0.1.50")
    m.append(_save(c, "attack_scan", "attack", ["scan"], ["10.0.1.50"], "nmap-style SYN scan of 1000 ports at ~500 pps"))
    c = cap(2); sc_ssh(c, T0, "10.0.1.51", n=60, interval=0.5)
    m.append(_save(c, "attack_ssh", "attack", ["ssh_bruteforce"], ["10.0.1.51"], "hydra-style SSH guessing, 60 attempts, last one succeeds"))
    c = cap(3); sc_smb(c, T0, "10.0.1.52", ["IPC$", "ADMIN$", "C$"])
    m.append(_save(c, "attack_smb", "attack", ["smb_admin"], ["10.0.1.52"], "smbclient-style access to IPC$, ADMIN$ and C$"))
    c = cap(4); sc_fuzz(c, T0, "10.0.1.53")
    m.append(_save(c, "attack_fuzz", "attack", ["web_fuzz"], ["10.0.1.53"], "ffuf-style wordlist fuzzing, 300 requests at 40 req/s"))

    # -- multi-stage chain -----------------------------------------------------------
    c = cap(5); a = "10.0.1.60"
    sc_fuzz(c, T0 + 60, a, n=200, rps=30)
    sc_scan(c, T0 + 180, a, ports=1000, pps=300)
    sc_ssh(c, T0 + 300, a, n=45, interval=1.0)
    sc_smb(c, T0 + 480, a, ["IPC$", "ADMIN$", "C$"])
    m.append(_save(c, "attack_chain", "chain", ["web_fuzz", "scan", "ssh_bruteforce", "smb_admin"], [a],
                   "One attacker walks the kill chain: recon, discovery, credential access, lateral movement",
                   attack_start=T0 + 60,
                   stage_start={"web_fuzz": T0 + 60, "scan": T0 + 180, "ssh_bruteforce": T0 + 300, "smb_admin": T0 + 480}))

    # -- benign baseline: 12 minutes of ordinary activity ----------------------------
    c = cap(6)
    r = c.rng
    for ip in ("10.0.2.21", "10.0.2.22"):
        t = T0 + r.uniform(5, 30)
        fav = True
        while t < T0 + 720:
            sc_browse(c, t, ip, pages=r.randint(1, 3), favicon=fav)
            fav = False
            t += r.uniform(40, 90)
    t = T0 + 20
    for _ in range(4):
        ssh_session(c, t, "10.0.3.5", b"SSH-2.0-OpenSSH_9.6\r\n", long_for=r.uniform(25, 80))
        t += r.uniform(120, 170)
    t = T0 + 45
    for _ in range(4):
        smb_session(c, t, "10.0.2.21", ["IPC$", "files"])
        t += r.uniform(100, 170)
    m.append(_save(c, "benign", "benign", [], [], "12 minutes of ordinary browsing, admin SSH sessions and file-share use"))

    # -- hard negatives: legitimate activity that LOOKS suspicious --------------------
    c = cap(7)
    for i in range(3):
        ssh_session(c, T0 + i * 9, "10.0.2.30", b"SSH-2.0-OpenSSH_9.6\r\n", long_for=40.0 if i == 2 else 0.0)
    m.append(_save(c, "hn_mistyped_password", "hardneg", [], [], "A user mistypes the SSH password twice, then logs in"))
    c = cap(8)
    for i in range(20):
        smb_session(c, T0 + i * 3, "10.0.3.20", ["IPC$", "backup"])
    m.append(_save(c, "hn_backup_job", "hardneg", [], [], "Nightly backup opens 20 SMB sessions to the named backup share"))
    c = cap(9)
    cn = Conn(c, T0, "10.0.2.31", VICTIM, 80).open()
    for i in range(46):
        http_get(cn.at(T0 + i * 0.4), f"/assets/img{i}.png" if i % 8 else f"/old/missing{i}.js", CHROME_UA, 404 if i % 8 == 0 else 200, 500)
    cn.close()
    m.append(_save(c, "hn_dev_404s", "hardneg", [], [], "A developer reloads a page with a few missing assets (6 x 404)"))
    c = cap(10)
    for i, p in enumerate((22, 80, 443, 445, 3306)):
        probe(c, T0 + i * 0.02, "10.0.3.5", VICTIM, p, "open" if p in (22, 80, 445) else "closed")
    m.append(_save(c, "hn_admin_portcheck", "hardneg", [], [], "An admin checks five known ports after a change window"))
    c = cap(11)
    for k in range(20):
        for i, p in enumerate((22, 80, 443, 445, 3306, 5432)):
            probe(c, T0 + k * 30 + i * 0.05, "10.0.3.9", VICTIM, p, "open" if p in (22, 80, 445) else "closed")
    m.append(_save(c, "hn_monitoring_poll", "hardneg", [], [], "Monitoring system polls six service ports every 30 s for 10 minutes"))
    c = cap(12)
    for i in range(120):
        cn = Conn(c, T0 + i, "10.0.3.10", VICTIM, 80).open()
        http_get(cn, "/health", "kube-probe/1.28", 200, 20)
        cn.close()
    m.append(_save(c, "hn_lb_healthcheck", "hardneg", [], [], "Load balancer health check, new connection every second for 2 minutes"))
    c = cap(13)
    for i in range(12):
        sc_browse(c, T0 + i * 0.25, "10.0.2.40", pages=1)
    m.append(_save(c, "hn_page_burst", "hardneg", [], [], "A busy single-page app opens 12 parallel connections at once"))

    # -- evasion cases -------------------------------------------------------------
    c = cap(14); sc_scan(c, T0, "10.0.1.70", ports=40, pps=1 / 8)
    m.append(_save(c, "ev_slow_scan", "evasion", ["scan"], ["10.0.1.70"], "Slow scan: one probe every 8 s (nmap -T1 style)"))
    c = cap(15); sc_ssh(c, T0, "10.0.1.71", n=24, interval=20.0, success=False)
    m.append(_save(c, "ev_slow_ssh", "evasion", ["ssh_bruteforce"], ["10.0.1.71"], "Throttled password guessing: one attempt every 20 s"))
    c = cap(16); sc_fuzz(c, T0, "10.0.1.72", n=80, rps=1 / 3, ua=CHROME_UA, conns=1)
    m.append(_save(c, "ev_slow_fuzz", "evasion", ["web_fuzz"], ["10.0.1.72"], "Slow fuzzing, browser user agent, one request every 3 s"))
    c = cap(17); sc_fuzz(c, T0, "10.0.1.73", n=200, rps=40, ua=CHROME_UA)
    m.append(_save(c, "ev_spoofed_ua", "evasion", ["web_fuzz"], ["10.0.1.73"], "Fast fuzzing that spoofs a browser user agent (defeats UA-only rules)"))
    c = cap(18); sc_smb(c, T0, "10.0.1.74", ["c$", "Admin$"])
    m.append(_save(c, "ev_smb_case", "evasion", ["smb_admin"], ["10.0.1.74"], "Admin share names in lower and mixed case"))
    c = cap(19); ips = [f"10.0.5.{i}" for i in range(1, 13)]
    for i, ip in enumerate(ips):
        sc_ssh(c, T0 + i * 4, ip, n=3, interval=5.0, success=False)
    m.append(_save(c, "ev_distributed_ssh", "evasion", ["ssh_bruteforce"], ips,
                   "Guessing spread over 12 source IPs (3 attempts each): known gap of per-source counting"))

    # -- robustness grid: same attack at decreasing speed -----------------------------
    for cls, rates, count in (("scan", GRID_RATES["scan"], 60), ("ssh_bruteforce", GRID_RATES["ssh_bruteforce"], 40),
                              ("web_fuzz", GRID_RATES["web_fuzz"], 80)):
        for j, rate in enumerate(rates):
            ip = f"10.0.4.{(len(m) % 200) + 10}"
            c = Cap(seed * 1000 + len(m))
            if cls == "scan":
                sc_scan(c, T0, ip, ports=count, pps=rate)
            elif cls == "ssh_bruteforce":
                sc_ssh(c, T0, ip, n=count, interval=1 / rate, success=False)
            else:
                sc_fuzz(c, T0, ip, n=count, rps=rate, conns=2, ua=CHROME_UA)  # behaviour only, no UA help
            name = f"grid_{cls}_{rate:g}"
            m.append(_save(c, name, "grid", [cls], [ip], f"{cls} at {rate:g} events/s", rate=rate))

    MANIFEST.write_text(json.dumps(m, indent=1), encoding="utf-8")
    return m


GRID_RATES = {
    "scan": [500, 50, 5, 0.5, 0.1, 0.03],
    "ssh_bruteforce": [2.0, 0.3, 0.1, 0.05, 0.02],
    "web_fuzz": [100, 20, 3, 1, 0.3, 0.05],
}


def load_manifest() -> list[dict]:
    if not MANIFEST.exists():
        return build_dataset()
    return json.loads(MANIFEST.read_text(encoding="utf-8"))
