# Tripwire — SMB Administrative Share Detection

**Technique:** MITRE ATT&CK T1021.002 (SMB / Windows Admin Shares)  
**Detector:** `rules/smb-detection.zeek`  
**Environment:** isolated Docker lab, Zeek 9.0.1, Samba 4.17.12 (Debian)  
**Experiments:** 21 November 2026  
**Status:** core detector implemented and validated in the controlled lab.

## 1. Problem and threat model

Administrative SMB shares, such as `ADMIN$` and `C$`, can support legitimate remote system administration. An adversary possessing valid credentials may also use them to access remote resources, transfer files, and prepare lateral movement. Simply detecting traffic to TCP 445 would create alerts for ordinary file sharing. The objective is to detect unexpected administrative share access, including denied attempts, without alerting on expected management or ordinary file traffic.

The lab simulates Windows-style administrative sharing with Samba. It does **not** simulate Windows remote service execution, and a share connection by itself does not prove a successful lateral movement compromise.

## 2. Research and design rationale

| Source | Finding relevant to design | Decision in our detector |
|---|---|---|
| MITRE ATT&CK T1021.002 [1] | Administrative shares can be abused with valid accounts. | Observe admin share access rather than merely failed authentication. |
| MITRE BZAR, sections 2 and 3.2 [2] | SMB tree-connect attempts to `ADMIN$` or `C$` are useful indicators even if unsuccessful; authorized activity needs environmental tuning. | Inspect tree-connect requests and configure expected management hosts. |
| BZAR configuration [3] | Repeated attempts are evaluated over five minutes with configurable thresholds of 5, 10, 15, 20, 30, 40, 50 and 100. | Compare the smallest published threshold (five) with a one-attempt policy violation in our lab. |
| Zeek SMB documentation and analyzer interface [4, 5, 6] | Zeek exposes higher-level share logs and individual SMB protocol events. | Match tree-connect requests and responses, rather than depend solely on successful mappings. |
| Microsoft NTSTATUS specification [7] | SMB replies communicate success, access denial and other errors, including missing share names. | Classify outcome using response status, not guess it from credentials or tool output. |
| MITRE DET0530 [8] | Higher-confidence lateral movement detection can correlate share access with subsequent execution and administrator context. | Implement an early-stage network indicator; reserve execution correlation for an optional Windows-capable extension. |

The decision to alert on one attempt is **our environment-specific policy**, not a threshold recommended universally by MITRE. In our isolated lab, only the designated admin host is expected to access administrative shares. One unexpected request is therefore meaningful. In production, this policy would require an accurate inventory and carefully maintained exceptions.

## 3. Lab configuration and ground truth

| Role | IP | Normal SMB behavior |
|---|---|---|
| Victim | `172.30.77.10` | Provides SMB2+ `Documents` and `ADMIN$` shares on TCP 445. `C$` is absent. |
| Attacker test host | `172.30.77.20` | Used to generate suspicious attempts, but the rule does not hard-code it as malicious. |
| Client | `172.30.77.30` | Normally accesses `Documents`; also used as the source of controlled unexpected administrative access. |
| Admin | `172.30.77.40` | Designated management host; allowed by detection policy. |

`labuser` may access `Documents`; `labadmin` may access `ADMIN$`. The lab uses dummy passwords. The SMB detector does not enforce access control; Samba determines authorization. The detector monitors the outcomes. All experiments were directed only at the team's isolated victim container.

Ground truth was obtained from the commands actually executed and the resulting `smbclient` output and exit status. The PCAP and Zeek events are the independent observation used for detection. Replay of a saved PCAP is not a new attack trial.

## 4. Hypotheses and visibility experiments

| ID | Hypothesis | Experiment and result | Decision |
|---|---|---|---|
| H1 | Successful share mappings alone can cover administrative access attempts. | Denied `ADMIN$` request produced an `IPC$` mapping but no `ADMIN$` mapping; successful requests produced the expected `ADMIN$` mapping. | Rejected as sole feature. |
| H2 | Tree-connect request and matching response can reveal the share and outcome. | Custom probe found the requested `ADMIN$` path and corresponding status for granted and denied cases. Later captured missing `C$` outcome. | Supported for observed unencrypted SMB2 sessions. |
| H3 | An unexpected source role is more informative than a known attacker IP or credential validity alone. | Normal client triggered alerts when reaching admin shares; attacker host's normal Documents access did not. Authorized admin generated no alert. | Supported in the defined lab policy. |
| H4 | Case normalization avoids a superficial name variation bypass. | Unexpected lowercase `admin$` with valid credentials was detected. | Supported for tested case variation. |
| H5 | A five-attempt frequency rule is sufficient. | Isolated unexpected requests stayed below five; five authorized requests reached five. | Rejected as sole criterion in this lab. |
| H6 | A single unexpected admin share attempt with response classification can detect isolated and repeated attempts without alerting on allowed activity. | Custom Zeek detector emitted the expected alerts across initial, validation and comparison captures, and none on observed benign controls. | Selected for the core requirement. |

### 4.1 Capture and analysis

Initial visibility PCAP: 515 packets captured, zero kernel drops reported by `tcpdump`. Initial SMB observations included one normal Documents access, one denied unexpected access, and two successful administrative accesses (one authorized, one unexpected).

```bash
docker compose exec victim tcpdump -i eth0 -nn -s 0 -U \
  -w /captures/visibility.pcap
```

The first Zeek replay warned of invalid TCP checksums, consistent with checksum offloading in the virtual network. A replay with `-C` recovered the relevant application-layer records. This is an explicit lab-capture workaround, not a recommendation to ignore checksum validation indiscriminately in production.

Relevant logs: `conn.log`, `smb_mapping.log`, `ntlm.log`, and `smb_files.log`. A normal NTLM authentication result can be successful while subsequent share authorization fails. For example, `labuser` successfully authenticated but was denied `ADMIN$`.

### 4.2 Protocol-level probe

The visibility script (`rules/smb-visibility.zeek`) logs the identity of each tree-connect request and corresponding response. Core probe logic:

```zeek
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header,
                                path: string)
    {
    print fmt("REQUEST uid=%s message=%d src=%s path=%s",
              c$uid, hdr$message_id, c$id$orig_h, path);
    }

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool)
    {
    if (!is_orig && hdr$command == 3)
        print fmt("RESPONSE uid=%s message=%d status=%d",
                  c$uid, hdr$message_id, hdr$status);
    }
```

SMB2 command 3 is TREE_CONNECT. Connection UID plus SMB message ID identifies the request within the replay. Message ID alone is insufficient: several separate connections all used message ID 7. Zeek-generated UIDs may differ between replays, so match records only within the same replay.

| Decimal status | Hexadecimal | Meaning | Output classification |
|---:|---|---|---|
| 0 | `0x00000000` | Success | `ACCESS_GRANTED` |
| 3221225506 | `0xC0000022` | `STATUS_ACCESS_DENIED` | `ACCESS_DENIED` |
| 3221225676 | `0xC00000CC` | `STATUS_BAD_NETWORK_NAME` (missing share) | `OTHER_ERROR` |

These statuses were confirmed using both SMB protocol responses and client output, not inferred from the presence of an alert.

## 5. Final implementation

One custom rule implements a combination of conditions, not five independent rules:

1. Recognize the exact terminal share names `ADMIN$` and `C$`, case-insensitively. `IPC$` is excluded because it is a named pipe and routinely appeared during legitimate access.
2. Exclude the configured management host, not the attacker IP. The exclusion is a lab policy assumption.
3. Store the request by `(connection UID, SMB message ID)`.
4. Match the server's final tree-connect response and classify its status.
5. Generate an ATT&CK-tagged notice on the first unexpected attempt with an observed final response, whether granted or denied.

Core Zeek implementation (excerpted/reformatted for readability; deployed source of truth is `rules/smb-detection.zeek`):

```zeek
@load base/frameworks/notice
module Tripwire;

export {
    redef enum Notice::Type += { SMB_Admin_Share };
    const management_hosts: set[addr] = {172.30.77.40} &redef;
}

global pending: table[string, count] of string &write_expire=1min;

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header,
                                path: string)
    {
    if (/\\(ADMIN\$|C\$)$/ !in to_upper(path)) return;
    if (c$id$orig_h in management_hosts) return;
    pending[c$uid, hdr$message_id] = path;
    }

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool)
    {
    if (is_orig || hdr$command != 3) return;
    if ([c$uid, hdr$message_id] !in pending) return;
    if (hdr$status == 259) return; # STATUS_PENDING, not final

    local path = pending[c$uid, hdr$message_id];
    local result = "OTHER_ERROR";
    if (hdr$status == 0) result = "ACCESS_GRANTED";
    else if (hdr$status == 3221225506) result = "ACCESS_DENIED";

    NOTICE([$note=SMB_Admin_Share, $conn=c,
        $msg=fmt("T1021.002: Unexpected admin share access: %s result=%s status=%d",
                 path, result, hdr$status),
        $identifier=fmt("%s:%d", c$uid, hdr$message_id)]);
    delete pending[c$uid, hdr$message_id];
    }
```

The one-minute expiry bounds stale pending-request state; it is not the detection threshold. Expiry and intermediate `STATUS_PENDING` behavior were not independently stress-tested. The event identifier distinguishes separate requests so repetition does not collapse them to one notice. The repeated-attempt experiment confirmed separate notices for five different connections.

## 6. Test procedure and results

The following commands use lab-only credentials. For each run, start capture on the victim before sending traffic and stop it after completing the scenario, then run Zeek on the saved PCAP. Record terminal output independently.

### 6.1 Initial visibility/development tests (4 operations)

| Source | Share | Actual outcome | Detector |
|---|---|---|---|
| Client | `Documents` | Granted | No alert |
| Attacker | `ADMIN$` with `labuser` | Denied | Alert |
| Admin | `ADMIN$` with `labadmin` | Granted | No alert |
| Attacker | `ADMIN$` with `labadmin` | Granted | Alert |

Example command:

```bash
docker compose exec -T attacker smbclient '//victim/ADMIN$' \
  -U 'labuser%LabUser123' -c 'ls'
```

Evidence: `captures/visibility.pcap`, `logs/visibility-corrected/`, `logs/smb-visibility/notice.log`.

### 6.2 Fresh validation (7 operations, one attempt per case)

| ID | Source and command arguments (to `smbclient`) | Actual command result | Expected alert | Observed |
|---|---|---|---|---|
| V1 | client: `//victim/ADMIN$`, `labuser`, `ls` | Access denied, exit 1 | Yes, denied | Yes |
| V2 | client: `//victim/admin$`, `labadmin`, `ls` | Granted, exit 0 | Yes, granted | Yes |
| V3 | attacker: `//victim/C$`, `labadmin`, `ls` | Bad network name, exit 1 | Yes, other error | Yes |
| V4 | attacker: `//victim/Documents`, `labuser`, `ls` | Granted, exit 0 | No | No |
| V5 | admin: `//victim/ADMIN$`, `labadmin`, `ls` | Granted, exit 0 | No | No |
| V6 | client: `-L victim`, `labuser` | Listing returned Documents and IPC$, exit 0; SMB1 fallback rejected | No | No |
| V7 | client: `//victim/ADMIN$`, `labadmin` with incorrect password | Session setup logon failure, exit 1 | Outside rule scope | No |

V7 fails authentication before reaching TREE_CONNECT. It is neither a true negative nor a false negative for the scoped share-attempt rule; a separate credential-abuse detector would be needed. V6's SMB1 fallback error was expected with the SMB2+ setup, and ordinary share listing succeeded.

Evidence: `captures/smb-validation.pcap`, `evidence/smb-validation-traffic.txt`, `logs/smb-validation/notice.log`, `evidence/smb-validation-events.txt`.

### 6.3 Benign control traffic (~10 minutes, 25 counted SMB operations)

20 iterations of normal client web, SSH and Documents activity, with an authorized administrative access every fourth iteration and a 30-second pause between iterations:

```bash
for i in $(seq 1 20); do
    docker compose exec -T client curl -s http://victim/
    docker compose exec -T client sshpass -p LabUser123 ssh \
        -o StrictHostKeyChecking=no labuser@victim 'echo Normal session'
    docker compose exec -T client smbclient '//victim/Documents' \
        -U 'labuser%LabUser123' -c 'ls'
    if [ $((i % 4)) -eq 0 ]; then
        docker compose exec -T admin smbclient '//victim/ADMIN$' \
            -U 'labadmin%LabAdmin123' -c 'ls'
        docker compose exec -T client curl -s -o /dev/null \
            http://victim/missing-image.png
    fi
    sleep 30
done
```

Additional file activity was generated; `report.txt` (24 bytes) was visible during validation. It is excluded from the counted denominator to avoid overstating the number of independently verified operations. No SMB notices were reported on the benign capture.

Evidence: `captures/benign.pcap`, `logs/smb-benign/` (no notice file reported in replay).

### 6.4 Comparative burst experiment (10 operations)

```bash
{
    for i in $(seq 1 5); do
        date -u
        docker compose exec -T attacker smbclient '//victim/ADMIN$' \
            -U 'labuser%LabUser123' -c 'ls'
        echo "Exit code: $?"
        sleep 1
    done
    for i in $(seq 1 5); do
        date -u
        docker compose exec -T admin smbclient '//victim/ADMIN$' \
            -U 'labadmin%LabAdmin123' -c 'ls'
        echo "Exit code: $?"
        sleep 1
    done
} 2>&1 | tee evidence/smb-comparison-traffic.txt
```

All five unexpected attempts were denied and produced separate notices. All five authorized accesses returned exit 0 and produced no notices. Both bursts occurred within seconds, far below BZAR's example five-minute interval.

The first unexpected response notice timestamp was `1795238700.688896`; the fifth was `1795238706.310550`. Difference: approximately **5.62 seconds**. In this observed sequence, a five-attempt threshold would have been reached only at the fifth attempt, whereas our rule alerted on the first. This measures the difference between first and fifth observed response times, not production processing performance.

Evidence: `captures/smb-comparison.pcap`, `evidence/smb-comparison-traffic.txt`, `evidence/smb-comparison-events.txt`, `logs/compare-smb-comparison/notice.log`.

### 6.5 Replay commands

```bash
for capture in smb-validation smb-comparison; do
    mkdir -p "logs/compare-$capture"
    docker run --rm --network none \
        -v "$PWD/captures:/pcaps:ro" \
        -v "$PWD/rules:/rules:ro" \
        -v "$PWD/logs/compare-$capture:/out" \
        -w /out --entrypoint zeek zeek/zeek:latest \
        -C -r "/pcaps/$capture.pcap" \
        /rules/smb-visibility.zeek /rules/smb-detection.zeek \
        LogAscii::use_json=T | tee "evidence/$capture-events.txt"
done
```

## 7. Comparative evaluation and rule selection

Alternative criteria were evaluated retrospectively against observed tree-connect paths, sources and responses. Only variant D was deployed and executed as our custom Zeek detector. We did not install or benchmark MITRE BZAR itself; the five-attempt comparator is a simplified criterion inspired by BZAR's published settings. A fairer success-only implementation might also include the same management exclusion (A+).

| Scenario | A: success only | A+: success with allowlist | B: ≥5 requests/5 min | C: B + allowlist | D: selected rule |
|---|---|---|---|---|---|
| Unexpected single denied request | Miss | Miss | Miss | Miss | Detected |
| Unexpected single granted request | Detected | Detected | Miss | Miss | Detected |
| Unexpected request to nonexistent C$ | Miss | Miss | Miss | Miss | Detected |
| Five unexpected denied requests | Miss | Miss | Detected | Detected | Detected |
| Five authorized admin requests | False alert | Correct | False alert | Correct | Correct |
| Normal Documents access | Correct | Correct | Correct | Correct | Correct |

Decision: D best covers the specified isolated and repeated attack scenarios within the known management policy. C does control the authorized burst false positive; the principal remaining advantage of D is detection of single unexpected accesses, with an explicit server outcome. We do not claim D dominates all other approaches in all production environments. A frequency rule could be valuable when admin access is common and reliable management context is unavailable.

## 8. Measured performance

Unit of evaluation: individual SMB operations, not packets, retransmissions, or replay repetitions. The burst experiments repeat the same scenario under nearly identical conditions; they are not statistically independent samples of distinct attack populations.

| Test type | Initial | Validation | Comparison | Benign | Total |
|---|---:|---:|---:|---:|---:|
| Unexpected denied | 1 | 1 | 5 | 0 | 7 |
| Unexpected granted | 1 | 1 | 0 | 0 | 2 |
| Unexpected missing share | 0 | 1 | 0 | 0 | 1 |
| **Positive operations** | **2** | **3** | **5** | **0** | **10** |
| Authorized admin | 1 | 1 | 5 | 5 | 12 |
| Normal Documents | 1 | 1 | 0 | 20 | 22 |
| Ordinary share listing | 0 | 1 | 0 | 0 | 1 |
| **Counted negative operations** | **2** | **3** | **5** | **25** | **35** |
| Out of scope (failed session authentication) | 0 | 1 | 0 | 0 | 1 |

| Metric | Observed result |
|---|---:|
| True positive | 10 |
| False negative (within declared scope) | 0 |
| True negative | 35 |
| False positive | 0 |
| Observed recall | 10/10 = 100% |
| Observed false-positive rate | 0/35 = 0% |

The initial two positives were also used to develop the detector. The fresh validation and comparison captures contain eight positive and eight negative operations, in addition to the separately captured 25 benign controls. Counts represent the observed operations in this lab. They are not estimates of production accuracy. Rare cases were validated once, and repeated operations do not establish robustness to new networks, encrypted traffic, missing packets or novel evasion techniques.

Representative notice messages recorded from actual outputs:

```text
T1021.002: Unexpected admin share access: \\victim\ADMIN$ result=ACCESS_DENIED status=3221225506
T1021.002: Unexpected admin share access: \\victim\admin$ result=ACCESS_GRANTED status=0
T1021.002: Unexpected admin share access: \\victim\C$ result=OTHER_ERROR status=3221225676
```

## 9. Limitations, evasions and operational considerations

| Limitation or evasion | Impact | Possible response (not implemented or validated here) |
|---|---|---|
| Compromised designated admin host | Allowlist hides its administrative share activity. | Monitor management hosts for unexpected users, processes, timing and subsequent actions; replace broad exceptions with scoped policy. |
| SMB3 encryption | Network monitor may not see share name or inner status. | Correlate server-side SMB auditing, authentication and endpoint telemetry. |
| Session authentication fails before tree connect | No share access event exists for this detector. | Separate SMB authentication-failure analytics. |
| Final response absent, lost or delayed beyond state expiry | Detector may not emit a classified alert. | Emit a separate lower-confidence pending-request notice or use server logs; test missing and reordered packets. |
| Other drive letters or custom administrative shares | Exact-name match only covers `ADMIN$` and `C$`. | Configure organization-specific administrative shares. |
| IP reuse, NAT, inaccurate asset roles | Host-based policy could misclassify requests. | Incorporate asset identity and authenticated management context. |
| Full Windows lateral movement not exercised | Share access is an indicator, not proof of execution/compromise. | Windows-capable endpoint lab and DET0530-style post-access correlation. |

For a demonstrable evasion, a request from the designated admin host is excluded by design. Legitimate admin access was tested; a compromised admin-host scenario has not been independently emulated. Treat this as an explained limitation, not a completed adversarial validation.

## 10. ATT&CK mapping and conclusion

Primary mapping: **T1021.002**, Remote Services — SMB/Windows Admin Shares. The rule identifies unexpected successful and attempted administrative share access. It does not claim confirmed remote execution, payload transfer (T1570), or credential theft. A future incident correlation layer can combine a successful unexpected share access with independent evidence of post-access behavior for greater confidence.

The chosen detector is explainable, uses current Zeek protocol-level telemetry, requires no training dataset, and is practical within the hackathon time budget. Its value comes from identifying policy violations on the first observed response while distinguishing access and authorization outcomes, not from inventing an arbitrary threshold. The experiments demonstrate scoped effectiveness and justify the choice over simpler mapping-only or repetition-only criteria.

## References

1. MITRE ATT&CK, [T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/).
2. MITRE ATT&CK, [BZAR: Zeek analytics, tuning and indicators](https://github.com/mitre-attack/bzar/blob/master/README.md), sections 2, 3.1, 3.2, 4.1.
3. MITRE ATT&CK, [BZAR configuration options](https://github.com/mitre-attack/bzar/blob/master/scripts/bzar_config_options.zeek), `bzar2_epoch`, `bzar2_limit`.
4. Zeek, [SMB Logs (plus DCE-RPC, Kerberos, NTLM)](https://docs.zeek.org/en/current/reference/logs/smb.html).
5. Zeek 9.0.1, [SMB2 TREE_CONNECT analyzer events](https://docs.zeek.org/en/lts/scripts/base/bif/plugins/Zeek_SMB.smb2_com_tree_connect.bif.zeek.html).
6. Zeek, [Protocol analyzers reference](https://docs.zeek.org/en/current/reference/zeekscript/proto-analyzers.html).
7. Microsoft Open Specifications, [MS-ERREF — NTSTATUS Values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55), and [SMB Tree Connect failure troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/negotiate-session-setup-tree-connect-fails).
8. MITRE ATT&CK, [DET0530 — Multi-Event Detection for SMB Admin Share Lateral Movement](https://attack.mitre.org/detectionstrategies/DET0530/), AN1468.

All external references were consulted during design or validation. Primary experimental evidence is in the local capture, rule and log paths specified above; those files should be retained in the submission repository.
