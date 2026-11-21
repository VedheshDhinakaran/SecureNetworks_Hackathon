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
- **What is observed:** One source sends many TCP SYNs, to many different ports.
- **Why it indicates the behavior:** A scanner probes a large port range quickly. Legitimate clients talk to a few well-known ports.
- **Layer 1 threshold:** 30 events within 5 s (Suricata sid 1000001)
- **Layer 2 threshold:** 15 events within 300 s (Zeek script)
- **Known evasion:** nmap -T1 style slow scanning stays under the short window. Layer 2 counts distinct ports over 5 minutes instead.
- **D3FEND:** Connection Attempt Analysis, Network Traffic Analysis
- **Mitigations:** Network Intrusion Prevention (M1031), Filter Network Traffic (M1037)

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
- **What is observed:** An SMB tree-connect to C$, D$ or ADMIN$ (IPC$ is excluded: it is routine).
- **Why it indicates the behavior:** Administrative shares expose whole disks. Ordinary file-share traffic uses named shares, never C$ or ADMIN$.
- **Signature:** tree-connect to an administrative share (Suricata sids 1000031, 1000032; Zeek notice)
- **Known evasion:** SMB3 encryption hides the share name from the sensor; host-side auditing is then needed. Case changes do not evade (matching is case-insensitive).
- **D3FEND:** Network Traffic Analysis, Protocol Metadata Anomaly Detection
- **Mitigations:** Network Segmentation (M1030), Limit Access to Resource Over Network (M1035), Filter Network Traffic (M1037)
