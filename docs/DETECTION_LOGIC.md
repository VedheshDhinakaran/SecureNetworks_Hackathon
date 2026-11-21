# Detection logic

Generated from `detections/catalog.yml`. Two layers: **L1** (Suricata, short window, fast) and **L2** (Zeek and native, long window, catches slow and low attacks).

## Web wordlist fuzzing (T1595.003 Wordlist Scanning)

- **Tactic:** Reconnaissance (TA0043)
- **What is observed:** A burst of HTTP 404 responses returned to a single client.
- **Why it indicates the behavior:** Wordlist fuzzers request hundreds of guessed paths; almost all miss and return 404. Normal browsing produces a handful of 404s at most.
- **Layer 1 threshold:** 15 events within 10 s (Suricata sid 1000041)
- **Layer 2 threshold:** 25 events within 300 s (Zeek script)
- **Known evasion:** Slow the rate below the short window, or spoof the user agent. Layer 2 (5-minute window) still counts the misses.
- **D3FEND:** Network Traffic Analysis, Protocol Metadata Anomaly Detection
- **Mitigations:** Filter Network Traffic (M1037), Exploit Protection (M1050)

## Port scanning / service discovery (T1046 Network Service Discovery)

- **Tactic:** Discovery (TA0007)
- **What is observed:** One source sends TCP connection attempts to many DIFFERENT ports of one target, answered or not (rejected, open or silently dropped).
- **Why it indicates the behavior:** A scanner probes a port range. Legitimate clients talk to a few well-known ports, and repeated attempts to one port (retries, busy web clients) do not raise the distinct-port count.
- **Layer 1 threshold:** 100 events within 5 s (Suricata sid 1000001)
- **Layer 2 threshold:** 10 events within 300 s (Zeek script)
- **Known evasion:** A slow scan stays under the short window; layer 2 counts distinct ports over a sliding 5 minutes. Fewer than 10 distinct ports (for example a 9-port scan) stays below the threshold (known gap), as does a scan slower than 10 ports per 5 minutes or one spread over many sources.
- **D3FEND:** Connection Attempt Analysis, Network Traffic Analysis
- **Mitigations:** Network Intrusion Prevention (M1031), Filter Network Traffic (M1037)
- **Tuning note:** Layer 2 started at 15 and missed a quick 14-port scan and a slow 10-port scan; the sweep put the safe band at 7-10 and we chose 10, matching the independent lab study in Port_Scan_Detection_Report.md. Layer 1 started at 30 and false-alerted on 30 rapid connections to ONE port (retries, a busy script); the safe band became 31-1000 and we chose 100.

## SSH password guessing (T1110.001 Password Guessing)

- **Tactic:** Credential Access (TA0006)
- **What is observed:** Many new TCP connections to port 22 from one source.
- **Why it indicates the behavior:** Each password guess is a new SSH connection. People rarely open more than a few sessions in a minute; guessers open dozens.
- **Layer 1 threshold:** 6 events within 30 s (Suricata sid 1000011)
- **Layer 2 threshold:** 14 events within 300 s (Zeek script)
- **Known evasion:** Throttle to one guess every 15-20 s. Layer 2 counts connections over 5 minutes. Guessing spread across many source IPs evades per-source counting (known gap).
- **D3FEND:** Connection Attempt Analysis, Network Traffic Analysis
- **Mitigations:** Account Use Policies (M1036), Network Intrusion Prevention (M1031), Limit Access to Resource Over Network (M1035)
- **Tuning note:** L2 started at 10 and false-positived on the monitoring-poll hard negative (11 SSH checks in 5 min). Sweep showed a safe band of 12-15; chose 14.

## SMB administrative share access (T1021.002 SMB/Windows Admin Shares)

- **Tactic:** Lateral Movement (TA0008)
- **What is observed:** An SMB tree-connect to C$, D$ or ADMIN$ from outside the management subnet. IPC$ is excluded (routine). The server's answer (granted, denied, share missing) is recorded.
- **Why it indicates the behavior:** Administrative shares expose whole disks. Ordinary file-share traffic uses named shares, never C$ or ADMIN$. A refused request is still an attempt, so we alert on the request, not only on successful mappings.
- **Signature:** tree-connect to an administrative share (Suricata sids 1000031, 1000032; Zeek notice)
- **Known evasion:** SMB3 encryption hides the share name from the sensor. Case changes do not evade (matching is case-insensitive). A compromised designated admin host is allowlisted by design and therefore invisible (known gap).
- **D3FEND:** Network Traffic Analysis, Protocol Metadata Anomaly Detection
- **Mitigations:** Network Segmentation (M1030), Limit Access to Resource Over Network (M1035), Filter Network Traffic (M1037)
