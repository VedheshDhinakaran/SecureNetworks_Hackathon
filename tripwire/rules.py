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
    mgmt = cat["meta"]["mgmt_subnet"]
    out += [f"# {c['title']} - {c['technique']} {c['technique_name']}",
            f"# IPC$ is excluded (routine). The designated management subnet {mgmt} is allowlisted by policy: only an",
            "# unexpected source role makes an administrative share request suspicious (see SMB_Detection_Report.md).",
            f'alert smb ![{mgmt}] any -> $HOME_NET any (msg:"TRIPWIRE SMB ADMIN$ share tree-connect (L1)"; flow:to_server,established; '
            f'smb.share; content:"ADMIN$"; nocase; classtype:attempted-admin; sid:{c["sid"]}; rev:1; '
            f'{_meta(c, "smb_admin", "L1")};)',
            f'alert smb ![{mgmt}] any -> $HOME_NET any (msg:"TRIPWIRE SMB C$/D$/E$ drive share tree-connect (L1)"; flow:to_server,established; '
            f'smb.share; pcre:"/\\x5c[c-e]\\x24$/i"; classtype:attempted-admin; sid:{c["sid_aux"]}; rev:1; '
            f'{_meta(c, "smb_admin", "L1")};)', ""]
    c = k["web_fuzz"]
    out += [f"# {c['title']} - {c['technique']} {c['technique_name']}",
            f'alert http any any -> any any (msg:"TRIPWIRE WEB-FUZZ 403/404 flood to one client (L1)"; flow:established,to_client; '
            f'http.stat_code; pcre:"/^40[34]$/"; threshold:type both, track by_dst, count {c["l1"]["count"]}, seconds {c["l1"]["window"]}; '
            f'classtype:web-application-attack; sid:{c["sid"]}; rev:1; {_meta(c, "web_fuzz", "L1")};)',
            f'# Layer 1 is a RATE rule: Suricata cannot count distinct paths or an error ratio, so it only fires on a loud flood.',
            f'# The contextual rule (distinct failing paths + error ratio) lives in the Zeek layer.',
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
    redef enum Notice::Type += { Port_Scan, SSH_Bruteforce, SSH_Auth_Failures, HTTP_Fuzzing, SMB_Admin_Share, SMB_Admin_Share_Result };
}

# SSH password guessing, attempt-weighted (design from SSH_Detection_Report.md). SSH is encrypted, so Zeek INFERS the
# outcome and the number of authentication attempts of each session from packet sizes. Tools like hydra reuse one
# connection for many guesses, so counting connections undercounts them. Only the final result of FAILED sessions
# counts; a successful or unknown (no inferred result) session contributes zero.
const ssh_att_window: interval = @@SSHATT_WINDOW@@sec;
type FailedSession: record {
    ts: time;
    attempts: count;
};
global ssh_failures: table[addr, addr] of table[string] of FailedSession &write_expire=1hr;

# Designated administration hosts: allowlisted by policy, not by attacker address (SMB_Detection_Report.md, H3).
const mgmt_net: subnet = @@MGMT_NET@@;
# admin-share requests waiting for the server's answer: (connection uid, SMB message id) -> requested path
global smb_pending: table[string, count] of string &write_expire=1min;

# Port scan state (design from Port_Scan_Detection_Report.md): for every (source, destination) PAIR, the last time each
# destination port was probed. Entries older than the window are pruned on every event, so the window slides
# instead of resetting in blocks. A port counts whether the probe was refused, answered or silently dropped.
const scan_window: interval = @@SCAN_WINDOW@@sec;
global scan_seen: table[addr, addr] of table[port] of time &write_expire=1hr;
# ports a destination actively refused (TCP RST), kept only to report how many probes were rejected
global scan_rejected: table[addr, addr] of set[port] &write_expire=1hr;

# per-source state that forgets itself after the window
global ssh_conns:  table[addr] of count    &create_expire=@@SSH_WINDOW@@sec;

# HTTP wordlist fuzzing, contextual (design from HTTP_Detection_Report.md). For every (source, destination, port) service a
# sliding window keeps each GET transaction: its path with the query string removed and whether it failed (403/404). The
# alert needs ALL of: enough errors, enough DISTINCT failing paths, and a majority of the client's requests failing.
# Volume alone is not enough: repeated requests for one missing asset, a changing query string and a broken application
# are all benign shapes that must stay silent.
const http_window: interval = @@HTTP_WINDOW@@sec;
const http_error_threshold: count = @@HTTP_ERRORS@@;
const http_path_threshold: count = @@HTTP_PATHS@@;
const http_min_error_ratio: double = @@HTTP_RATIO@@;
type HTTPObservation: record {
    ts: time;
    path: string;
    is_error: bool;
};
global http_activity: table[addr, addr, port] of table[string] of HTTPObservation &write_expire=1hr;

event new_connection(c: connection)
    {
    if ( get_port_transport_proto(c$id$resp_p) != tcp )
        return;
    if ( c$id$resp_h !in @@HOME_NET@@ )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # T1046: many distinct destination ports of ONE target from one source, inside a sliding window
    local now = network_time();
    local recent: table[port] of time = table();
    if ( [src, dst] in scan_seen )
        recent = scan_seen[src, dst];
    local stale: set[port] = set();
    for ( sp in recent )
        {
        if ( now - recent[sp] > scan_window )
            add stale[sp];
        }
    for ( old_port in stale )
        delete recent[old_port];
    recent[c$id$resp_p] = now;
    scan_seen[src, dst] = recent;

    if ( |recent| >= @@SCAN_COUNT@@ )
        {
        local refused = 0;
        if ( [src, dst] in scan_rejected )
            {
            for ( rp in recent )
                {
                if ( rp in scan_rejected[src, dst] )
                    ++refused;
                }
            }
        NOTICE([$note=Port_Scan, $conn=c,
                $msg=fmt("%s probed %d distinct ports of %s within @@SCAN_WINDOW@@s (%d refused)", src, |recent|, dst, refused),
                $identifier=fmt("%s:%s", src, dst), $suppress_for=scan_window]);
        }

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

# T1110.001: inferred authentication attempts inside FAILED sessions, in a sliding window per source-destination pair
event ssh_auth_result(c: connection, result: bool, auth_attempts: count)
    {
    if ( result || auth_attempts == 0 )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local now = network_time();
    local recent: table[string] of FailedSession = table();
    if ( [src, dst] in ssh_failures )
        recent = ssh_failures[src, dst];

    local stale: set[string] = set();
    for ( uid in recent )
        {
        if ( now - recent[uid]$ts > ssh_att_window )
            add stale[uid];
        }
    for ( old_uid in stale )
        delete recent[old_uid];

    recent[c$uid] = [$ts=now, $attempts=auth_attempts];
    ssh_failures[src, dst] = recent;

    local total: count = 0;
    for ( session in recent )
        total += recent[session]$attempts;

    if ( total >= @@SSHATT_COUNT@@ )
        NOTICE([$note=SSH_Auth_Failures, $conn=c,
                $msg=fmt("T1110.001: %d inferred auth attempts across %d failed SSH sessions from %s within @@SSHATT_WINDOW@@s", total, |recent|, src),
                $identifier=fmt("%s:%s", src, dst), $suppress_for=ssh_att_window]);
    }

# context for the scan alert: which probes the target actively refused (TCP RST, conn_state REJ)
event connection_rejected(c: connection)
    {
    if ( [c$id$orig_h, c$id$resp_h] !in scan_rejected )
        scan_rejected[c$id$orig_h, c$id$resp_h] = set();
    add scan_rejected[c$id$orig_h, c$id$resp_h][c$id$resp_p];
    }

# T1595.003: contextual wordlist-fuzzing detection over parsed HTTP transactions
event HTTP::log_http(rec: HTTP::Info)
    {
    if ( ! rec?$method || ! rec?$uri || ! rec?$status_code )
        return;
    if ( rec$method != "GET" )
        return;

    local src = rec$id$orig_h;
    local dst = rec$id$resp_h;
    local dest_port = rec$id$resp_p;
    local now = network_time();
    local path = sub(rec$uri, /\?.*$/, "");
    local is_error = rec$status_code == 403 || rec$status_code == 404;

    local recent: table[string] of HTTPObservation = table();
    if ( [src, dst, dest_port] in http_activity )
        recent = http_activity[src, dst, dest_port];

    local stale: set[string] = set();
    for ( key in recent )
        {
        if ( now - recent[key]$ts > http_window )
            add stale[key];
        }
    for ( old_key in stale )
        delete recent[old_key];

    local transaction = fmt("%s:%d", rec$uid, rec$trans_depth);
    recent[transaction] = [$ts=now, $path=path, $is_error=is_error];
    http_activity[src, dst, dest_port] = recent;

    local errors: count = 0;
    local unique_paths: set[string] = set();
    for ( entry in recent )
        {
        if ( recent[entry]$is_error )
            {
            ++errors;
            add unique_paths[recent[entry]$path];
            }
        }
    local ratio = count_to_double(errors) / count_to_double(|recent|);

    if ( errors >= http_error_threshold && |unique_paths| >= http_path_threshold && ratio >= http_min_error_ratio )
        NOTICE([$note=HTTP_Fuzzing, $uid=rec$uid, $id=rec$id, $src=src, $dst=dst, $p=dest_port,
                $msg=fmt("T1595.003: %d errors, %d distinct paths, %d GET requests, error ratio %.2f within @@HTTP_WINDOW@@s",
                         errors, |unique_paths|, |recent|, ratio),
                $identifier=fmt("%s:%s:%s", src, dst, dest_port), $suppress_for=http_window]);
    }

# T1021.002: tree-connect to an administrative share (IPC$ is routine and excluded).
# 1) the request raises the alert immediately, so a lost or delayed reply never hides an attempt
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
    {
    if ( c$id$orig_h in mgmt_net )
        return;
    local p = to_upper(path);
    if ( strstr(p, "\\ADMIN$") > 0 || strstr(p, "\\C$") > 0 || strstr(p, "\\D$") > 0 || strstr(p, "\\E$") > 0 )
        {
        smb_pending[c$uid, hdr$message_id] = path;
        NOTICE([$note=SMB_Admin_Share, $conn=c,
                $msg=fmt("%s requested administrative share %s", c$id$orig_h, path),
                $identifier=cat(c$id$orig_h, path), $suppress_for=1min]);
        }
    }

# 2) the server's answer classifies the outcome (a refused request still matters; success-only logs miss it)
event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool)
    {
    if ( is_orig || hdr$command != 3 )          # 3 = TREE_CONNECT
        return;
    if ( [c$uid, hdr$message_id] !in smb_pending )
        return;
    if ( hdr$status == 259 )                    # STATUS_PENDING is not final
        return;
    local path = smb_pending[c$uid, hdr$message_id];
    delete smb_pending[c$uid, hdr$message_id];
    local result = "OTHER_ERROR";
    if ( hdr$status == 0 )
        result = "ACCESS_GRANTED";
    else if ( hdr$status == 3221225506 )        # 0xC0000022 STATUS_ACCESS_DENIED
        result = "ACCESS_DENIED";               # (0xC00000CC STATUS_BAD_NETWORK_NAME stays OTHER_ERROR)
    NOTICE([$note=SMB_Admin_Share_Result, $conn=c, $sub=result,
            $msg=fmt("%s administrative share %s result=%s status=%d", c$id$orig_h, path, result, hdr$status),
            $identifier=fmt("%s:%d", c$uid, hdr$message_id)]);
    }
'''


def zeek_script() -> str:
    cat = load_catalog()
    k = cat["classes"]
    rep = {
        "@@SCAN_WINDOW@@": k["scan"]["l2"]["window"], "@@SCAN_COUNT@@": k["scan"]["l2"]["count"],
        "@@SSH_WINDOW@@": k["ssh_bruteforce"]["l2"]["window"], "@@SSH_COUNT@@": k["ssh_bruteforce"]["l2"]["count"],
        "@@HTTP_WINDOW@@": k["web_fuzz"]["l2"]["window"], "@@HTTP_ERRORS@@": k["web_fuzz"]["l2"]["errors"],
        "@@HTTP_PATHS@@": k["web_fuzz"]["l2"]["count"], "@@HTTP_RATIO@@": k["web_fuzz"]["l2"]["ratio"],
        "@@HOME_NET@@": cat["meta"]["home_net"], "@@MGMT_NET@@": cat["meta"]["mgmt_subnet"],
        "@@SSHATT_WINDOW@@": k["ssh_bruteforce"]["attempts"]["window"], "@@SSHATT_COUNT@@": k["ssh_bruteforce"]["attempts"]["count"],
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
