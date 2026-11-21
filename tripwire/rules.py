"""Detection-as-code: render Suricata rules and the Zeek script from detections/catalog.yml."""
from __future__ import annotations

from .config import RULES_DIR, ZEEK_DIR, load_catalog


def _meta(c: dict, cls: str, layer: str) -> str:
    return (f"metadata:mitre_technique_id {c['technique']}, mitre_tactic {c['tactic'].lower().replace(' ', '_')}, "
            f"tripwire_class {cls}, tripwire_layer {layer}, tripwire_severity {c['severity']}")


def suricata_rules() -> str:
    cat = load_catalog()
    k = cat["classes"]
    out = [
        "# =====================================================================",
        "# Tripwire Layer-1 (fast) Suricata rules.",
        "# GENERATED from detections/catalog.yml by `python -m tripwire build-rules`.",
        "# Do not edit by hand: change thresholds in the catalog instead.",
        "# NOTE: time-window rules are only reliable when Suricata runs single-threaded on a PCAP",
        "# (--runmode single). In the default multi-threaded offline mode flows are processed out of time",
        "# order and the same rule gave nondeterministic results (found by the evasion matrix).",
        "# =====================================================================",
        "",
    ]
    c = k["scan"]
    out += [f"# {c['title']} - {c['technique']} {c['technique_name']}",
            f'alert tcp any any -> $HOME_NET any (msg:"TRIPWIRE SCAN SYN sweep from one source (L1)"; flow:to_server; '
            f'flags:S,12; threshold:type both, track by_src, count {c["l1"]["count"]}, seconds {c["l1"]["window"]}; '
            f'classtype:network-scan; sid:{c["sid"]}; rev:1; {_meta(c, "scan", "L1")};)', ""]
    c = k["ssh_bruteforce"]
    out += [f"# {c['title']} - {c['technique']} {c['technique_name']}",
            f'alert tcp any any -> $HOME_NET 22 (msg:"TRIPWIRE SSH password guessing: connection burst (L1)"; flow:to_server; '
            f'flags:S,12; threshold:type both, track by_src, count {c["l1"]["count"]}, seconds {c["l1"]["window"]}; '
            f'classtype:attempted-admin; sid:{c["sid"]}; rev:1; {_meta(c, "ssh_bruteforce", "L1")};)', ""]
    c = k["smb_admin"]
    out += [f"# {c['title']} - {c['technique']} {c['technique_name']}  (IPC$ deliberately excluded)",
            f'alert smb any any -> $HOME_NET any (msg:"TRIPWIRE SMB ADMIN$ share tree-connect (L1)"; flow:to_server,established; '
            f'smb.share; content:"ADMIN$"; nocase; classtype:attempted-admin; sid:{c["sid"]}; rev:1; '
            f'{_meta(c, "smb_admin", "L1")};)',
            f'alert smb any any -> $HOME_NET any (msg:"TRIPWIRE SMB C$/D$/E$ drive share tree-connect (L1)"; flow:to_server,established; '
            f'smb.share; pcre:"/\\x5c[c-e]\\x24$/i"; classtype:attempted-admin; sid:{c["sid_aux"]}; rev:1; '
            f'{_meta(c, "smb_admin", "L1")};)', ""]
    c = k["web_fuzz"]
    out += [f"# {c['title']} - {c['technique']} {c['technique_name']}",
            f'alert http any any -> any any (msg:"TRIPWIRE WEB-FUZZ 404 burst to one client (L1)"; flow:established,to_client; '
            f'http.stat_code; content:"404"; threshold:type both, track by_dst, count {c["l1"]["count"]}, seconds {c["l1"]["window"]}; '
            f'classtype:web-application-attack; sid:{c["sid"]}; rev:1; {_meta(c, "web_fuzz", "L1")};)',
            f'# Auxiliary signal only: user agents are trivially spoofed (see evasion matrix).',
            f'alert http any any -> $HOME_NET any (msg:"TRIPWIRE WEB-FUZZ known fuzzer user agent (aux)"; flow:established,to_server; '
            f'http.user_agent; pcre:"/(fuzz faceless|gobuster|sqlmap|nikto|wfuzz|dirbuster)/i"; '
            f'classtype:web-application-attack; sid:{c["sid_aux"]}; rev:1; '
            f'{_meta(c, "web_fuzz", "L1")};)', ""]
    return "\n".join(out)


ZEEK_TEMPLATE = r'''##! Tripwire Layer-2 (long-window, behavioural) Zeek detections.
##! GENERATED from detections/catalog.yml by `python -m tripwire build-rules`. Do not edit by hand.
##! Layer 2 exists to catch what Suricata's short windows miss: slow and low attacks.

@load base/frameworks/notice
@load base/protocols/http
@load base/protocols/smb
@load base/protocols/ssh

redef LogAscii::use_json = T;

module Tripwire;

export {
    redef enum Notice::Type += { Port_Scan, SSH_Bruteforce, Web_Fuzz, SMB_Admin_Share };
}

# per-source state that forgets itself after the window
global scan_ports: table[addr] of set[port] &create_expire=@@SCAN_WINDOW@@sec;
global ssh_conns:  table[addr] of count    &create_expire=@@SSH_WINDOW@@sec;
global fuzz_404s:  table[addr] of count    &create_expire=@@FUZZ_WINDOW@@sec;

event new_connection(c: connection)
    {
    if ( get_port_transport_proto(c$id$resp_p) != tcp )
        return;
    if ( c$id$resp_h !in @@HOME_NET@@ )
        return;

    local src = c$id$orig_h;

    # T1046: many distinct destination ports from one source
    if ( src !in scan_ports )
        scan_ports[src] = set();
    add scan_ports[src][c$id$resp_p];
    if ( |scan_ports[src]| == @@SCAN_COUNT@@ )
        NOTICE([$note=Port_Scan, $conn=c,
                $msg=fmt("%s probed %d distinct ports within @@SCAN_WINDOW@@s", src, @@SCAN_COUNT@@),
                $identifier=cat(src), $suppress_for=10min]);

    # T1110.001: many new SSH connections from one source
    if ( c$id$resp_p == 22/tcp )
        {
        if ( src !in ssh_conns )
            ssh_conns[src] = 0;
        ++ssh_conns[src];
        if ( ssh_conns[src] == @@SSH_COUNT@@ )
            NOTICE([$note=SSH_Bruteforce, $conn=c,
                    $msg=fmt("%s opened %d SSH connections within @@SSH_WINDOW@@s", src, @@SSH_COUNT@@),
                    $identifier=cat(src), $suppress_for=10min]);
        }
    }

# T1595.003: many 404 responses to one client
event http_reply(c: connection, version: string, code: count, reason: string)
    {
    if ( code != 404 )
        return;
    local src = c$id$orig_h;
    if ( src !in fuzz_404s )
        fuzz_404s[src] = 0;
    ++fuzz_404s[src];
    if ( fuzz_404s[src] == @@FUZZ_COUNT@@ )
        NOTICE([$note=Web_Fuzz, $conn=c,
                $msg=fmt("%s received %d HTTP 404 responses within @@FUZZ_WINDOW@@s", src, @@FUZZ_COUNT@@),
                $identifier=cat(src), $suppress_for=10min]);
    }

# T1021.002: tree-connect to an administrative share (IPC$ is routine and excluded)
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
    {
    local p = to_upper(path);
    if ( strstr(p, "\\ADMIN$") > 0 || strstr(p, "\\C$") > 0 || strstr(p, "\\D$") > 0 || strstr(p, "\\E$") > 0 )
        NOTICE([$note=SMB_Admin_Share, $conn=c,
                $msg=fmt("%s accessed administrative share %s", c$id$orig_h, path),
                $identifier=cat(c$id$orig_h, path), $suppress_for=1min]);
    }
'''


def zeek_script() -> str:
    cat = load_catalog()
    k = cat["classes"]
    rep = {
        "@@SCAN_WINDOW@@": k["scan"]["l2"]["window"], "@@SCAN_COUNT@@": k["scan"]["l2"]["count"],
        "@@SSH_WINDOW@@": k["ssh_bruteforce"]["l2"]["window"], "@@SSH_COUNT@@": k["ssh_bruteforce"]["l2"]["count"],
        "@@FUZZ_WINDOW@@": k["web_fuzz"]["l2"]["window"], "@@FUZZ_COUNT@@": k["web_fuzz"]["l2"]["count"],
        "@@HOME_NET@@": cat["meta"]["home_net"],
    }
    s = ZEEK_TEMPLATE
    for a, b in rep.items():
        s = s.replace(a, str(b))
    return s


def build_rules() -> list[str]:
    RULES_DIR.mkdir(exist_ok=True)
    ZEEK_DIR.mkdir(exist_ok=True)
    (RULES_DIR / "tripwire.rules").write_text(suricata_rules(), encoding="utf-8", newline="\n")
    (ZEEK_DIR / "tripwire.zeek").write_text(zeek_script(), encoding="utf-8", newline="\n")
    return [str(RULES_DIR / "tripwire.rules"), str(ZEEK_DIR / "tripwire.zeek")]


# ---------------------------------------------------------------- lint (detection-as-code hygiene)
def lint_rules() -> tuple[bool, str]:
    import re
    cat = load_catalog()["classes"]
    text = (RULES_DIR / "tripwire.rules").read_text(encoding="utf-8")
    sids, problems = [], []
    for line in text.splitlines():
        if not line.startswith("alert"):
            continue
        sid = re.search(r"sid:(\d+);", line)
        tech = re.search(r"mitre_technique_id (T\d+(?:\.\d+)?)", line)
        cls = re.search(r"tripwire_class (\w+)", line)
        if not (sid and tech and cls):
            problems.append(f"rule missing sid/technique/class: {line[:60]}")
            continue
        sids.append(sid.group(1))
        if cat.get(cls.group(1), {}).get("technique") != tech.group(1):
            problems.append(f"sid {sid.group(1)}: technique {tech.group(1)} does not match catalog for {cls.group(1)}")
    if len(sids) != len(set(sids)):
        problems.append("duplicate sids")
    return (not problems), (f"{len(sids)} rules, all carry ATT&CK IDs matching the catalog, sids unique" if not problems else "; ".join(problems))


def lint_sigma() -> tuple[bool, str]:
    import yaml
    from .config import ROOT
    cat = load_catalog()["classes"]
    known = {c["technique"].lower() for c in cat.values()}
    files = sorted((ROOT / "sigma").glob("*.yml"))
    problems = []
    for f in files:
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        for k in ("title", "id", "status", "logsource", "detection", "tags", "level"):
            if k not in d:
                problems.append(f"{f.name}: missing {k}")
        techs = {t[len("attack."):].upper() for t in d.get("tags", []) if t.lower().startswith("attack.t")}
        if not (techs & {k.upper() for k in known}):
            problems.append(f"{f.name}: no tag matches a catalog technique")
    return (not problems and bool(files)), (f"{len(files)} Sigma rules valid and tagged with catalog techniques" if not problems and files else "; ".join(problems) or "no Sigma rules found")


def lint_checks() -> list[dict]:
    ok1, d1 = lint_rules()
    ok2, d2 = lint_sigma()
    return [{"name": "Hygiene: every Suricata rule carries a matching ATT&CK technique ID", "ok": ok1, "detail": d1},
            {"name": "Hygiene: Sigma rules are structurally valid and ATT&CK-tagged", "ok": ok2, "detail": d2}]
