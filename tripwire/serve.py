"""Live platform: ingest sensor output as it arrives, correlate, explain, serve a live dashboard.

Two ingest modes feed the SAME pipeline:
  tail    follow data/live/suricata/eve.json and data/live/zeek/*.log written by the sensors in the Docker lab
  replay  stream the events of a finished run in timestamp order at an accelerated clock (demo safety net:
          identical downstream behaviour, no dependence on live packet capture working on the laptop)
State is persisted to SQLite (out/tripwire.db).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import engines as eng
from . import rca, respond
from .config import DATA, OUT, PCAPS
from .correlate import correlate
from .evidence import Evidence
from .gen import load_manifest
from .report import DASH

LIVE_DIR = DATA / "live"
MARK = "window.__STATE__ = /*__STATE__*/null;"


class Store:
    def __init__(self, path: Path = OUT / "tripwire.db"):
        OUT.mkdir(exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("create table if not exists events(id integer primary key, ts real, sensor text, cls text, src text, body text)")
        self.db.execute("delete from events")
        self.lock = threading.Lock()

    def add(self, e: dict) -> None:
        with self.lock:
            self.db.execute("insert into events(ts,sensor,cls,src,body) values(?,?,?,?,?)", (e["ts"], e["sensor"], e["class"], e["src"], json.dumps(e)))
            self.db.commit()

    def all(self) -> list[dict]:
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("select body from events order by ts")]


class Tailer:
    def __init__(self, path: Path):
        self.path, self.pos = path, 0

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        if self.path.stat().st_size < self.pos:      # file was truncated or rotated (sensor restart): start over
            self.pos = 0
        with open(self.path, "rb") as fh:
            fh.seek(self.pos)
            data = fh.read()
            nl = data.rfind(b"\n")
            if nl < 0:
                return []
            self.pos += nl + 1
        for line in data[:nl].decode("utf-8", "replace").splitlines():
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out


class Platform:
    def __init__(self, base: dict, mode: str, speed: float = 30.0, only: list[str] | None = None):
        self.base, self.mode, self.speed = base, mode, speed
        self.store = Store()
        self.lock = threading.Lock()
        self.state = dict(base, live=True, alerts=[], incidents=[], rca={}, response=[])
        self.rca_cache: dict[tuple, dict] = {}
        self.live_ev = Evidence("zeek logs (live)")
        self.man = {m["name"]: m for m in load_manifest()}
        self.only = only
        self._last_alert: dict[tuple, float] = {}
        self.tailers = {"eve": Tailer(LIVE_DIR / "suricata" / "eve.json"), "notice": Tailer(LIVE_DIR / "zeek" / "notice.log"),
                        "conn": Tailer(LIVE_DIR / "zeek" / "conn.log"), "http": Tailer(LIVE_DIR / "zeek" / "http.log"),
                        "smb": Tailer(LIVE_DIR / "zeek" / "smb_mapping.log")}

    # ---- ingest
    def pending_replay(self) -> list[dict]:
        evs = [e for e in self.base.get("alerts", []) if not self.only or e.get("pcap") in self.only]
        return sorted(evs, key=lambda e: e["ts"])

    def pull_tail(self) -> list[dict]:
        new = []
        for j in self.tailers["eve"].read():
            if j.get("event_type") == "alert":
                e = eng.normalize_suricata(j, "live")
                if e and not e.get("aux"):
                    new.append(e)
        for j in self.tailers["notice"].read():
            e = eng.normalize_zeek_notice(j, "live")
            if e:
                new.append(e)
        for j in self.tailers["conn"].read():
            h = j.get("history", "") or ""
            self.live_ev.add_conn(j["ts"], j["id.orig_h"], j["id.resp_h"], j["id.resp_p"], "h" in h,
                                  j.get("duration"), (j.get("orig_bytes") or 0) + (j.get("resp_bytes") or 0))
        for j in self.tailers["http"].read():
            self.live_ev.add_http(j["ts"], j["id.orig_h"], j.get("uri", ""), j.get("status_code", 0), j.get("user_agent", ""))
        for j in self.tailers["smb"].read():
            self.live_ev.add_smb(j["ts"], j["id.orig_h"], j.get("path", ""))
        return new

    def evidence_for(self, inc: dict) -> Evidence:
        if self.mode == "tail":
            return self.live_ev
        pc = inc["pcaps"][0]
        return eng.evidence_for(PCAPS / self.man[pc]["file"])

    # ---- recompute
    def refresh(self) -> None:
        events = self.store.all()
        incs = correlate(events)
        rcas = {}
        for inc in incs:
            key = (inc["src"], len(inc["stages"]), self.mode == "tail" and int(inc["end"]))
            if key not in self.rca_cache:
                try:
                    self.rca_cache[key] = rca.analyse(inc, self.evidence_for(inc))
                except Exception as exc:       # keep the platform alive on odd data
                    self.rca_cache[key] = {"incident": inc["id"], "src": inc["src"], "evidence_source": f"error: {exc}",
                                           "stages": [], "root_causes": [], "verification": {"rows": [], "cleared": 0, "total": 0}}
            r = dict(self.rca_cache[key])
            r["incident"] = inc["id"]
            rcas[inc["id"]] = r
        with self.lock:
            self.state.update(alerts=events[-500:], incidents=incs, rca=rcas, response=respond.plan(incs))

    def snapshot(self) -> dict:
        with self.lock:
            return dict(self.state)

    # ---- loops
    def run(self) -> None:
        if self.mode == "replay":
            evs = self.pending_replay()
            if not evs:
                return
            t_prev = evs[0]["ts"]
            for e in evs:
                time.sleep(max(0.0, min(2.0, (e["ts"] - t_prev) / self.speed)))
                t_prev = e["ts"]
                self.store.add(e)
                self.refresh()
        else:
            while True:
                new = self.pull_tail()
                kept = 0
                for e in new:
                    k = (e["sensor"], e["rule"], e["src"], e.get("dport"))
                    if e["ts"] - self._last_alert.get(k, -1e9) <= 60:      # collapse bursts, same as engines.aggregate
                        self._last_alert[k] = e["ts"]
                        continue
                    self._last_alert[k] = e["ts"]
                    self.store.add(e)
                    kept += 1
                if kept:
                    self.refresh()
                time.sleep(1.0)


def serve(port: int = 8765, mode: str = "replay", speed: float = 30.0, only: list[str] | None = None, log=print, host: str = "127.0.0.1") -> None:
    sp = OUT / "state.json"
    if not sp.exists():
        raise SystemExit("No results yet. Run `python -m tripwire test` first.")
    base = json.loads(sp.read_text(encoding="utf-8"))
    plat = Platform(base, mode, speed, only)
    threading.Thread(target=plat.run, daemon=True).start()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body: bytes, ctype: str):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.startswith("/api/state"):
                self._send(json.dumps(plat.snapshot(), default=str).encode(), "application/json")
            elif self.path == "/" or self.path.startswith("/index"):
                html = DASH.read_text(encoding="utf-8").replace(
                    MARK, "window.__LIVE__ = true; window.__STATE__ = " + json.dumps(plat.snapshot(), default=str).replace("</", "<\\/") + ";")
                self._send(html.encode(), "text/html; charset=utf-8")
            else:
                self.send_error(404)

    srv = ThreadingHTTPServer((host, port), H)
    log(f"Tripwire live dashboard: http://{host if host != '0.0.0.0' else 'localhost'}:{port}  (mode={mode}"
        + (f", {speed:g}x clock" if mode == "replay" else ", following data/live/") + ")  Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
