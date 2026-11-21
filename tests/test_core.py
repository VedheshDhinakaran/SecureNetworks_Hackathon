"""Fast unit tests. Run: python -m pytest -q"""
from pathlib import Path

from tripwire import correlate, gen, native, rca, rules
from tripwire.evidence import Evidence


def test_window_maths():
    assert native.window_cross([0, 1, 2, 3, 100], 3, 5) == 2
    assert native.window_cross([0, 10, 20], 3, 5) is None
    assert native.window_max([0, 1, 2, 50], 10) == 3
    assert native.unique_cross([(0, 1), (1, 2), (2, 2), (3, 3)], 3, 10) == 3
    assert native.unique_max([(0, 1), (1, 2), (400, 3)], 10) == 2


def test_generator_and_detector_agree(tmp_path: Path):
    c = gen.Cap(1)
    gen.sc_ssh(c, gen.T0, "10.0.1.99", n=20, interval=0.5, success=False)
    p = tmp_path / "ssh.pcap"
    c.write(p)
    ev = native.detect(native.parse_pcap(p))
    assert {e["class"] for e in ev} == {"ssh_bruteforce"}


def test_benign_traffic_is_silent(tmp_path: Path):
    c = gen.Cap(2)
    for i in range(3):
        gen.ssh_session(c, gen.T0 + i * 9, "10.0.2.30", b"SSH-2.0-OpenSSH_9.6\r\n")
    gen.sc_browse(c, gen.T0 + 5, "10.0.2.22", pages=2, favicon=True)
    p = tmp_path / "ok.pcap"
    c.write(p)
    assert native.detect(native.parse_pcap(p)) == []


def test_smb_admin_detected_ipc_ignored(tmp_path: Path):
    c = gen.Cap(3)
    gen.sc_smb(c, gen.T0, "10.0.1.98", ["IPC$"])
    p = tmp_path / "a.pcap"
    c.write(p)
    assert native.detect(native.parse_pcap(p)) == []
    c = gen.Cap(4)
    gen.sc_smb(c, gen.T0, "10.0.1.98", ["IPC$", "c$"])
    p = tmp_path / "b.pcap"
    c.write(p)
    assert {e["class"] for e in native.detect(native.parse_pcap(p))} == {"smb_admin"}


def _ev(ts, cls, tech, tactic, sensor="suricata"):
    return {"ts": ts, "sensor": sensor, "layer": "L1", "class": cls, "rule": "r", "src": "10.0.1.9", "dst": "10.0.0.10",
            "dport": 0, "technique": tech, "tactic": tactic, "severity": 1, "pcap": "x"}


def test_correlation_builds_ordered_high_risk_incident():
    evs = [_ev(0, "web_fuzz", "T1595.003", "Reconnaissance"), _ev(60, "scan", "T1046", "Discovery"),
           _ev(120, "ssh_bruteforce", "T1110.001", "Credential Access"), _ev(120, "ssh_bruteforce", "T1110.001", "Credential Access", "zeek")]
    inc = correlate.correlate(evs)
    assert len(inc) == 1 and inc[0]["kill_chain_ordered"] and inc[0]["risk"] >= 9
    assert [s["class"] for s in inc[0]["stages"]] == ["web_fuzz", "scan", "ssh_bruteforce"]


def test_config_reading_and_fix_ops():
    txt = "[global]\n   server signing = auto\n[C$]\n   path = /x\n"
    assert rca.read_directive(txt, "server signing", "global") == "auto"
    assert rca.section_exists(txt, "C$")
    out = rca.apply_ops({"smb.conf": txt}, [{"op": "set", "file": "smb.conf", "section": "global", "key": "server signing", "value": "mandatory"},
                                           {"op": "remove_section", "file": "smb.conf", "section": "C$"}])
    assert "mandatory" in out["smb.conf"] and "[C$]" not in out["smb.conf"]


def test_root_cause_confirms_weak_ssh_config():
    ev = Evidence("test")
    for i in range(30):
        ev.add_conn(i, "10.0.1.9", "10.0.0.10", 22, True, 0.4, 3000)
    inc = {"id": "INC-T", "src": "10.0.1.9", "stages": [{"class": "ssh_bruteforce", "title": "SSH"}]}
    r = rca.analyse(inc, ev)
    ids = {c["id"] for c in r["root_causes"]}
    assert {"ssh-password-auth", "ssh-no-attempt-limit", "flat-network"} <= ids
    assert r["verification"]["cleared"] >= 3


def test_rules_are_clean():
    rules.build_rules()
    assert rules.lint_rules()[0] and rules.lint_sigma()[0]


def test_smb_outcome_is_classified(tmp_path: Path):
    c = gen.Cap(5)
    gen.sc_smb(c, gen.T0, "10.0.1.97", [("ADMIN$", gen.ST_DENIED), "C$", "ADMIN$"], spacing=2.0)
    p = tmp_path / "o.pcap"
    c.write(p)
    ev = native.detect(native.parse_pcap(p))
    assert {e["outcome"] for e in ev} >= {"granted", "denied", "error"} or len(ev) >= 2
    assert any(e["outcome"] == "granted" for e in ev)


def test_denied_admin_share_attempt_still_alerts(tmp_path: Path):
    c = gen.Cap(6)
    gen.sc_smb(c, gen.T0, "10.0.1.96", [("ADMIN$", gen.ST_DENIED)])
    p = tmp_path / "d.pcap"
    c.write(p)
    ev = native.detect(native.parse_pcap(p))
    assert len(ev) == 1 and ev[0]["outcome"] == "denied"


def test_management_host_is_allowlisted(tmp_path: Path):
    c = gen.Cap(7)
    for i in range(5):
        gen.smb_session(c, gen.T0 + i, "10.0.3.5", [("ADMIN$", gen.ST_OK)])
    p = tmp_path / "m.pcap"
    c.write(p)
    assert native.detect(native.parse_pcap(p)) == []


def test_rca_impact_distinguishes_granted_from_refused():
    ev = Evidence("test")
    ev.add_smb(1, "10.0.1.9", r"\10.0.0.10\ADMIN$", "denied")
    assert rca.impact("smb_admin_reached", ev, "10.0.1.9")["level"] == "attempted"
    assert rca.ev_smb_admin_reached(ev, "10.0.1.9")[0] is False
    ev.add_smb(2, "10.0.1.9", r"\10.0.0.10\C$", "granted")
    assert rca.impact("smb_admin_reached", ev, "10.0.1.9")["level"] == "confirmed"
    assert rca.ev_smb_admin_reached(ev, "10.0.1.9")[0] is True


def test_ssh_attempts_prefer_zeeks_inferred_count():
    ev = Evidence("test")
    for i in range(5):                                  # 5 connections ...
        ev.add_conn(i, "10.0.1.9", "10.0.0.10", 22, True, 1.0, 500)
    assert ev.ssh_attempts("10.0.1.9") == 5             # ... without Zeek: count connections
    ev.add_ssh_auth(1, "10.0.1.9", False, 13)           # one failed session holding 13 guesses
    ev.add_ssh_auth(2, "10.0.1.9", False, 12)
    ev.add_ssh_auth(3, "10.0.1.9", None, 0)             # unknown outcome counts zero
    assert ev.ssh_attempts("10.0.1.9") == 25
    sm = ev.ssh_auth_summary("10.0.1.9")
    assert sm["failed_sessions"] == 2 and sm["unknown_sessions"] == 1


def test_ssh_success_after_failures_is_reported_as_inferred():
    ev = Evidence("test")
    ev.add_ssh_auth(1, "10.0.1.9", False, 13)
    ev.add_ssh_auth(2, "10.0.1.9", True, 14)
    imp = rca.impact("ssh_login_probable", ev, "10.0.1.9")
    assert imp["level"] == "probable" and "inferred" in imp["text"]


def test_rapid_successful_logins_are_not_guessing(tmp_path: Path):
    c = gen.Cap(8)
    for i in range(12):
        gen.ssh_session(c, gen.T0 + i * 2.0, "10.0.2.99", b"SSH-2.0-OpenSSH_9.6\r\n", long_for=1.0)
    p = tmp_path / "burst.pcap"
    c.write(p)
    assert native.detect(native.parse_pcap(p)) == []


def _http_pcap(tmp_path, name, reqs, rps=30.0):
    c = gen.Cap(40)
    cs = [gen.Conn(c, gen.T0, "10.0.2.88", gen.VICTIM, 80).open() for _ in range(2)]
    for k, (path, code) in enumerate(reqs):
        gen.http_get(cs[k % 2].at(gen.T0 + k / rps), path, gen.CHROME_UA, code, 300 if code == 200 else 0)
    for x in cs:
        x.close()
    p = tmp_path / f"{name}.pcap"
    c.write(p)
    return native.detect(native.parse_pcap(p))


def test_repeated_and_query_errors_are_not_fuzzing(tmp_path: Path):
    assert _http_pcap(tmp_path, "rep", [("/missing.png", 404)] * 120) == []
    assert _http_pcap(tmp_path, "qry", [(f"/missing.png?id={i}", 404) for i in range(120)]) == []


def test_broken_application_is_not_fuzzing(tmp_path: Path):
    reqs = [r for i in range(60) for r in (("/", 200), ("/", 200), (f"/missing-{i}.png", 404))]
    assert _http_pcap(tmp_path, "broken", reqs) == []


def test_http_thresholds_are_inclusive_and_independent(tmp_path: Path):
    assert _http_pcap(tmp_path, "b49", [(f"/t-{i}", 404) for i in range(49)]) == []                  # 49 errors
    assert _http_pcap(tmp_path, "b24", [(f"/t-{i % 24}", 404) for i in range(50)]) == []             # 24 distinct paths
    ev = _http_pcap(tmp_path, "b25", [(f"/t-{i % 25}", 404) for i in range(50)])                     # exactly 50 / 25
    assert {e["layer"] for e in ev} == {"L2"} and ev[0]["class"] == "web_fuzz"
