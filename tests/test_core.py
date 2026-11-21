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
