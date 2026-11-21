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
    redef enum Notice::Type += { Port_Scan, SSH_Bruteforce, Web_Fuzz, SMB_Admin_Share };
}

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

# T1021.002: tree-connect to an administrative share (IPC$ is routine and excluded)
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
    {
    local p = to_upper(path);
    if ( strstr(p, "\\ADMIN$") > 0 || strstr(p, "\\C$") > 0 || strstr(p, "\\D$") > 0 || strstr(p, "\\E$") > 0 )
        NOTICE([$note=SMB_Admin_Share, $conn=c,
                $msg=fmt("%s accessed administrative share %s", c$id$orig_h, path),
                $identifier=cat(c$id$orig_h, path), $suppress_for=1min]);
    }
