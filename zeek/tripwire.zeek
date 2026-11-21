##! Tripwire Layer-2 (long-window, behavioural) Zeek detections.
##! GENERATED from detections/catalog.yml by `python -m tripwire build-rules`. Do not edit by hand.
##! Layer 2 exists to catch what Suricata's short windows miss: slow and low attacks.

@load base/frameworks/notice
@load base/protocols/http
@load base/protocols/smb
@load base/protocols/ssh

redef LogAscii::use_json = T;

module Tripwire;

export {
    redef enum Notice::Type += { Port_Scan, SSH_Bruteforce, Web_Fuzz, SMB_Admin_Share, SMB_Admin_Share_Result };
}

# Designated administration hosts: allowlisted by policy, not by attacker address (SMB_Detection_Report.md, H3).
const mgmt_net: subnet = 10.0.3.0/24;
# admin-share requests waiting for the server's answer: (connection uid, SMB message id) -> requested path
global smb_pending: table[string, count] of string &write_expire=1min;

# per-source state that forgets itself after the window
global scan_ports: table[addr] of set[port] &create_expire=300sec;
global ssh_conns:  table[addr] of count    &create_expire=300sec;
global fuzz_404s:  table[addr] of count    &create_expire=300sec;

event new_connection(c: connection)
    {
    if ( get_port_transport_proto(c$id$resp_p) != tcp )
        return;
    if ( c$id$resp_h !in 10.0.0.0/24 )
        return;

    local src = c$id$orig_h;

    # T1046: many distinct destination ports from one source
    if ( src !in scan_ports )
        scan_ports[src] = set();
    add scan_ports[src][c$id$resp_p];
    if ( |scan_ports[src]| == 15 )
        NOTICE([$note=Port_Scan, $conn=c,
                $msg=fmt("%s probed %d distinct ports within 300s", src, 15),
                $identifier=cat(src), $suppress_for=10min]);

    # T1110.001: many new SSH connections from one source
    if ( c$id$resp_p == 22/tcp )
        {
        if ( src !in ssh_conns )
            ssh_conns[src] = 0;
        ++ssh_conns[src];
        if ( ssh_conns[src] == 14 )
            NOTICE([$note=SSH_Bruteforce, $conn=c,
                    $msg=fmt("%s opened %d SSH connections within 300s", src, 14),
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
    if ( fuzz_404s[src] == 25 )
        NOTICE([$note=Web_Fuzz, $conn=c,
                $msg=fmt("%s received %d HTTP 404 responses within 300s", src, 25),
                $identifier=cat(src), $suppress_for=10min]);
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
