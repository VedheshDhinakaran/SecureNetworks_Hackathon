# Tripwire — TCP Port Scan Detection

**Technique:** MITRE ATT&CK T1046 — Network Service Discovery  
**Final detector:** `rules/scan-tuned.zeek`, which loads `rules/scan-detection.zeek`  
**Original benchmark:** 15 distinct rejected ports in five minutes  
**Final lab configuration:** 10 distinct rejected ports in five minutes  
**Environment:** isolated Docker lab, Zeek 9.0.1, Nmap 7.991  
**Experimental date:** 21 November 2026

## 1. Objective and threat model

An adversary who has access to a network may enumerate a target's listening services before attempting exploitation or lateral movement. Port scanning generates connection attempts across multiple destination ports. The objective is to detect that behavior from network telemetry while distinguishing it from ordinary repeated connections, such as web traffic or retries to an unavailable service.

Scanning is not inherently malicious: authorized vulnerability assessments, maintenance and diagnostics may generate similar traffic. Our detector indicates possible reconnaissance; it does not prove hostile intent or successful compromise. Scope: TCP vertical scans (many ports on one target), using observed rejection events. The victim was `172.30.77.10`; test traffic originated from the attacker (`172.30.77.20`) and normal client (`172.30.77.30`). Port 22, 80 and 445 were open. No external system was targeted.

## 2. Research and hypothesis origin

| Research source | What it supports | Application in our design |
|---|---|---|
| Historical Zeek scan policy, v6.0.9 [1] | Defaults of 15 unique failed destination ports per target within 5 min; longer intervals may detect slower scans but increase false positives. | Use 15/5 min as the initial research-backed benchmark, then tune on captured traffic. |
| Zeek TCP analyzer event documentation [2] | `connection_rejected` represents a connection setup denied by a responder's RST. | Count observed rejection events instead of counting every TCP reset or every packet. |
| MITRE ATT&CK T1046 and DET0376 [3,4] | Service discovery can be detected from rapid connections to multiple services or hosts; scan-rate thresholds and time windows are configurable. | Use destination-port cardinality, source/destination grouping and time-window comparison. |
| Elastic's network scan rule and threshold-rule documentation [5,6] | Modern detection systems use unique destination-port counts, including different criteria for sensitive ports. | Compare total connection volume to distinct-port cardinality; do not assume one universal threshold. |
| Nmap official documentation [7,8] | TCP connect scans use OS connection attempts; closed ports normally respond with RST; open ports may also receive a reset after establishment. | Generate controlled `-sT` scans and distinguish `REJ` from established-then-reset connections. |

The value **15 rejected ports/5 minutes** comes from a historical implementation, not a universal research-proven optimum. The alternatives of 10 and 25 were chosen to examine sensitivity below and above that baseline. Neither 10 nor 25 is presented as a universally valid threshold. The one-minute comparison tests whether a shorter observation interval loses detection on slower activity.

## 3. Candidate hypotheses

| ID | Hypothesis | Expected rationale |
|---|---|---|
| H1 | At least 15 TCP connections in a rolling window indicate a scan. | Simple volume criterion, but normal traffic can also produce many connections. |
| H2 | At least 15 distinct TCP destination ports indicate a scan. | Cardinality distinguishes broad probing from repeated visits to one service. |
| H3 | At least 15 distinct rejected TCP ports indicate a scan. | Rejections provide evidence of probing unavailable services, which can increase specificity. |
| H4 | A lower rejected-port threshold (10) improves detection at acceptable false-positive cost in our lab. | Should detect narrower and mixed open/closed scans missed at 15. |
| H5 | A five-minute rolling window detects slower scans missed by a one-minute window. | The same distinct-port count can be spread across a longer period. |
| H6 | Source-destination grouping and independent port counting generalize beyond one attacker IP or fixed port range. | Test with a different client source and a new destination-port range. |

We separate research-supported hypotheses from experimentally tested results. In particular, H3 is not guaranteed to outperform H2: it deliberately ignores successful and silently filtered probes.

## 4. Visibility and feature selection

The initial Nmap scan targeted 101 ports (1–100 and 445). Nmap reported 98 closed ports and three open ports (22, 80, 445). The initial capture also contained later SSH, SMB and HTTP activity. Zeek replay with `-C` was necessary for this virtual-network capture because of checksum-offloading warnings; see SMB documentation for the initial visibility verification.

Observed aggregate `conn.log` data:

| Source / capture | Total TCP connections | Distinct ports | Distinct rejected ports | Rejection ratio |
|---|---:|---:|---:|---:|
| Attacker, `visibility.pcap` | 110 | 101 | 98 | 0.891 |
| Normal client, `visibility.pcap` | 3 | 3 | 0 | 0 |
| Admin, `visibility.pcap` | 1 | 1 | 0 | 0 |
| Normal client, `benign.pcap` | 66 | 3 | 0 | 0 |
| Admin, `benign.pcap` | 5 | 1 | 0 | 0 |

**Nuance:** 98/110 = 89.1% is the ratio of rejected attacker connections in the entire mixed capture, not the rejection ratio of the scan alone. Nmap itself reported 98/101 closed ports. A rule should not count every TCP RST as a failed connection: a legitimate established connection or the successful portion of a connect scan may terminate with RST. Zeek distinguishes `REJ` from states such as `RSTO` and `SF`.

Features selected:

- `id.orig_h` and `id.resp_h`: identify a communication pair, not a hard-coded attacker IP.
- `id.resp_p`: destination-port cardinality; repeated attempts to one port do not inflate it.
- Actual `connection_rejected` event: use an observed response as failure evidence.
- Packet/capture time (`network_time()`): supports rolling detection during PCAP replay and live processing.

Features not used as hard conditions:

- Raw packet count: a TCP connection may generate multiple packets and retransmissions.
- Total TCP connection count: busy traffic and retries can exceed a threshold without scanning ports.
- Rejection ratio: denominator depends on the surrounding traffic; a legitimate service outage can also create a high ratio. We examined the aggregate ratio but did not experimentally tune a ratio-based detector.
- Nmap identity or fixed port order: not required; the client shell test uses a different generator and port order is not part of the rule.

## 5. Custom Zeek implementation

The original rule was retained as a benchmark. The final configuration loads that rule and changes only the threshold.

`rules/scan-detection.zeek`:

```zeek
@load base/frameworks/notice
module Tripwire;

export {
    redef enum Notice::Type += { Port_Scan };
    option scan_threshold: count = 15;
    option scan_window: interval = 5min;
}

# MITRE ATT&CK: T1046
global scanned: table[addr, addr] of table[port] of time
    &write_expire=1hr;

event connection_rejected(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local now = network_time();
    local recent: table[port] of time = table();
    if ([src, dst] in scanned)
        recent = scanned[src, dst];

    local stale: set[port] = set();
    for (p in recent)
        {
        if (now - recent[p] > scan_window)
            add stale[p];
        }
    for (old_port in stale)
        delete recent[old_port];

    recent[c$id$resp_p] = now;
    scanned[src, dst] = recent;

    if (|recent| >= scan_threshold)
        {
        NOTICE([
            $note=Port_Scan,
            $conn=c,
            $msg=fmt(
                "T1046: %d distinct rejected ports from %s to %s within %s",
                |recent|, src, dst, scan_window
            ),
            $identifier=fmt("%s:%s", src, dst),
            $suppress_for=scan_window
        ]);
        }
    }
```

Final configuration, `rules/scan-tuned.zeek`:

```zeek
@load ./scan-detection
redef Tripwire::scan_threshold = 10;
```

Short-window comparison, `rules/scan-short-window.zeek` (not the final detector):

```zeek
@load ./scan-tuned
redef Tripwire::scan_window = 1min;
```

On every rejection, the rule removes ports last seen more than the configured window ago, updates the current port's timestamp, and checks cardinality. This avoids fixed time-bucket boundaries. The one-hour table expiry is a cleanup policy for inactive communication pairs; it is separate from the five-minute detection window. The notice identifier and suppression period reduce repetitive alerts for the same pair. Notice suppression is not an assertion that every scan episode is uniquely identified in continuous traffic: separate scans of the same pair within the suppression interval may be merged. Boundary tests used independent captures.

## 6. Experimental methodology and commands

Ground truth came from Nmap results, shell commands, timestamps, packet capture and their exit codes. Each fresh experiment had an independent capture to reset prior detector state. Replaying a capture with another configuration is a comparison, not an additional traffic trial.

Example capture-and-execute helper used in the test run (Bash):

```bash
run_scan_test() {
    name="$1"
    shift
    echo "=== $name ==="
    date -u
    docker compose exec -T victim sh -c '
        echo $$ > "/tmp/$1.pid"
        exec tcpdump -i eth0 -nn -s 0 -U \
          -w "/captures/$1.pcap"
    ' sh "$name" &
    capture_pid=$!
    sleep 2
    "$@"
    echo "Traffic command exit code: $?"
    sleep 1
    docker compose exec -T victim sh -c '
        kill -INT "$(cat "/tmp/$1.pid")"
    ' sh "$name"
    wait "$capture_pid"
    echo "=== Completed $name ==="
}
```

All commands below were executed against `victim` on the isolated lab. For Nmap cases the common options were `--unprivileged -sT -Pn -n`, and port ranges were supplied with `-p`. The original Nmap image wrapper initially failed with an operation-not-permitted error; after removing the excess file capability on `/usr/lib/nmap/nmap` in the attacker container, the unprivileged TCP connect scan succeeded. No privileged container was required.

### 6.1 Initial development tests

```bash
docker compose exec attacker nmap --unprivileged -sT -Pn -p 1-100,445 victim
```

The original rule alerted at 15 rejected ports, once. No notice was produced for the separately captured approximately ten-minute benign traffic. The tuned rule later alerted at 10 and likewise produced no benign notice.

### 6.2 First validation and tuning — eight independently generated captures

| Capture | Ground truth | Generator and arguments | Packets captured | Trials |
|---|---|---|---:|---:|
| `scan14` | Scan, 14 closed | Nmap `-p 1001-1014` | 28 | 1 |
| `scan15` | Scan, 15 closed | Nmap `-p 1001-1015` | 30 | 1 |
| `scan16-client` | Scan, 16 closed, normal client source | Bash `/dev/tcp`, ports 1001–1016 | 32 | 1 |
| `scan-retries` | Control, 30 attempts to same closed port | Bash `/dev/tcp`, 30 attempts to 1001 | 60 | 1 |
| `scan-normalweb` | Control, 30 requests to open HTTP service | `curl`, 30 requests | 300 | 1 |
| `scan-mixed15` | Scan, 12 closed + 3 open | Nmap `-p 22,80,445,1001-1012` | 36 | 1 |
| `scan-mixed18` | Scan, 15 closed + 3 open | Nmap `-p 22,80,445,1001-1015` | 42 | 1 |
| `scan-slow` | Scan, 16 closed, 88.20 seconds | Nmap `--scan-delay 5s -p 1001-1016` | 42 | 1 |

Representative exact traffic commands:

```bash
run_scan_test scan14 docker compose exec -T attacker nmap \
    --unprivileged -sT -Pn -n -p 1001-1014 victim

run_scan_test scan16-client docker compose exec -T client bash -c '
    for p in $(seq 1001 1016); do
        (echo > /dev/tcp/victim/$p) 2>/dev/null || true
    done'

run_scan_test scan-retries docker compose exec -T client bash -c '
    for i in $(seq 1 30); do
        (echo > /dev/tcp/victim/1001) 2>/dev/null || true
    done'

run_scan_test scan-normalweb docker compose exec -T client bash -c '
    for i in $(seq 1 30); do
        curl -fsS -o /dev/null http://victim/
    done'

run_scan_test scan-slow docker compose exec -T attacker nmap \
    --unprivileged -sT -Pn -n --scan-delay 5s -p 1001-1016 victim
```

The full experiment command transcript is in `evidence/scan-validation-traffic.txt`. Each capture reported zero kernel packet drops. Some tcpdump received-by-filter totals exceeded the captured totals; zero reported kernel drops does not prove complete visibility under arbitrary capture load. Zeek issued TCP-control-only trace warnings for the short scans and retry cases, which is consistent with connect probes that exchange control packets without application payload. The expected connection records and notices were nevertheless observed.

## 7. Feature and threshold comparison

We used `conn.log` records to retrospectively compute the maximum count in each rolling time window, with thresholds 10, 15 and 25. The actual Zeek detector was separately replayed at 15 and 10. The retrospective analysis used connection start timestamps rather than rejection event times, so it is not an exact implementation of event-based alert latency. Each fresh capture contained one relevant originating source; a pooled retrospective calculation would not be valid for multi-source captures without grouping by source and destination.

Core retrospective calculation:

```python
from collections import deque

def features(rows, window):
    recent = deque()
    maximum = [0, 0, 0]
    for r in sorted(rows, key=lambda r: r['ts']):
        recent.append(r)
        while recent and r['ts'] - recent[0]['ts'] > window:
            recent.popleft()
        values = [
            len(recent),
            len({x['id.resp_p'] for x in recent}),
            len({x['id.resp_p'] for x in recent
                 if x.get('conn_state') == 'REJ'})
        ]
        maximum = [max(a, b) for a, b in zip(maximum, values)]
    return maximum
```

### 7.1 Observed maximum features in 300 seconds

| Capture | Total | Distinct | Distinct rejected | H1 total ≥15 | H2 distinct ≥15 | H3 rejected ≥15 (actual) | Rejected ≥10 (actual) |
|---|---:|---:|---:|---|---|---|---|
| scan14 | 14 | 14 | 14 | Miss | Miss | Miss | Detected |
| scan15 | 15 | 15 | 15 | Detected | Detected | Detected | Detected |
| scan16-client | 16 | 16 | 16 | Detected | Detected | Detected | Detected |
| scan-retries | 30 | 1 | 1 | False positive | Correct | Correct | Correct |
| scan-normalweb | 30 | 1 | 0 | False positive | Correct | Correct | Correct |
| scan-mixed15 | 15 | 15 | 12 | Detected | Detected | Miss | Detected |
| scan-mixed18 | 18 | 18 | 15 | Detected | Detected | Detected | Detected |
| scan-slow | 17 | 16 | 16 | Detected | Detected | Detected | Detected |

`scan-slow` produced 17 connection records but only 16 unique ports, further supporting distinct-port counting. Its maximum in a 60-second window was 12 total, 12 distinct and 12 distinct rejected ports. A threshold of 15 with the shorter window would miss it. At threshold 10, the same slow capture would still be detected in 60 seconds, motivating a new slower holdout test.

| Variant, 5 minutes | Detected among six scan cases | False positives among two controls | Evidence |
|---|---:|---:|---|
| Total connections ≥15 | 5/6 | 2/2 | Retrospective |
| Distinct ports ≥15 | 5/6 | 0/2 | Retrospective |
| Distinct rejected ports ≥25 | 0/6 | 0/2 | Retrospective |
| Distinct rejected ports ≥15 | 4/6 | 0/2 | Executed Zeek rule |
| Distinct rejected ports ≥10 | 6/6 | 0/2 | Executed tuned Zeek rule |

### 7.2 Interpretation and decision

H1 fails the control cases: 30 repeated HTTP requests and 30 retries each exceed a raw count of 15. H2 has stronger coverage than H3 at threshold 15 because it detects the mixed scan with only 12 rejected ports. In this dataset, H2 at threshold 10 would also detect all six scans and flag neither control; **there is no empirical basis here to claim the rejection criterion is superior to all-distinct counting at the same threshold.** We retained the rejection-based detector because the observed rejection is an interpretable sign of unavailable-service probing, consistent with historical Zeek design. This choice trades coverage of open/filtered-only scanning for specificity in the defined scope. A production detector could add a distinct-all-ports or sensitive-port rule and treat rejection rate as context rather than a mandatory gate.

We chose 10/5 min because it recovered both missed scans at the original threshold without introducing a false alert on the observed controls. We do not indefinitely lower the threshold to detect every small probe: the experiments cannot estimate false-positive risk from legitimate diagnostics or larger multi-service environments. This is a lab-calibrated candidate, not a production optimum.

Evidence: `evidence/scan-feature-comparison.txt`, `logs/validation-scan*/`, `logs/tuned-scan*/`, `logs/scan-visibility/`, `logs/scan-benign/`, `logs/tuned-visibility/`, `logs/tuned-benign/`.

## 8. Independent holdout after tuning

Three fresh scenarios used a previously untested port range (2001–2010). This establishes the new threshold's behavior without simply reusing the tuning captures.

```bash
run_scan_test scan-holdout9 docker compose exec -T attacker nmap \
    --unprivileged -sT -Pn -n -p 2001-2009 victim
run_scan_test scan-holdout10 docker compose exec -T attacker nmap \
    --unprivileged -sT -Pn -n -p 2001-2010 victim
run_scan_test scan-holdout-slow docker compose exec -T attacker nmap \
    --unprivileged -sT -Pn -n --scan-delay 8s -p 2001-2010 victim
```

Each was generated once; both detector configurations were replayed on each same PCAP.

| Holdout | Ground truth | Nmap duration | 10 / 60 s | 10 / 300 s |
|---|---|---:|---|---|
| scan-holdout9 | 9 closed | 0.56 s | No alert | No alert (false negative) |
| scan-holdout10 | 10 closed | 0.57 s | Detected | Detected |
| scan-holdout-slow | 10 closed | 81.82 s | Missed | Detected |

Actual slow-scan notice: `T1046: 10 distinct rejected ports from 172.30.77.20 to 172.30.77.10 within 5.0 mins`. The same capture generated no notice using the one-minute configuration. This confirms H5 at the tuned threshold, not merely at the historical baseline. The nine-port test is an explicitly documented evasion/false negative, not a benign control. H6 is supported by the successful normal-client-origin scan and the alternative port range; cross-source aggregation behavior was not separately stress-tested.

Evidence: `evidence/scan-holdout-traffic.txt`, `captures/scan-holdout*.pcap`, `logs/scan-tuned-scan-holdout*/`, `logs/scan-short-window-scan-holdout*/`.

## 9. Reproducible replay and evidence

For a chosen capture and rule, use a clean output directory to avoid stale notices from previous runs:

```bash
capture=scan-holdout-slow
rule=scan-tuned
folder="logs/replay-$rule-$capture-$(date +%s)"
mkdir -p "$folder"

docker run --rm --network none \
    -v "$PWD/captures:/pcaps:ro" \
    -v "$PWD/rules:/rules:ro" \
    -v "$PWD/$folder:/out" \
    -w /out --entrypoint zeek zeek/zeek:latest \
    -C -r "/pcaps/$capture.pcap" \
    "/rules/$rule.zeek" LogAscii::use_json=T
```

Check `notice.log` if present, verify the Zeek command exited successfully, and inspect `conn.log` to confirm traffic was parsed. An absent notice is meaningful only when the input and replay are verified. Preserve the PCAPs, terminal ground truth, rule files, and separately named output folders. For the final demo, load **`scan-tuned.zeek`** rather than the historical default or short-window comparator; it transitively loads `scan-detection.zeek`.

## 10. Results and trial counts

Unit: one complete independently generated scan episode or control capture, not an individual port, packet or replay. Two controls contain 30 operations each, but those are two episodes, not 60 independent evaluations of the detector. The ten-minute benign capture is counted as one additional control.

| Phase | Attack episodes | Detected by final rule | Controls | False alerts |
|---|---:|---:|---:|---:|
| Initial visibility + benign | 1 | 1 | 1 | 0 |
| Initial tuning suite | 6 | 6 | 2 | 0 |
| Independent holdout | 3 | 2 | 0 | 0 |
| **Total** | **10** | **9** | **3** | **0** |

| Metric | Observed result |
|---|---:|
| True positives | 9 |
| False negatives | 1 |
| True negatives (control episodes) | 3 |
| False positives | 0 |
| Overall observed recall | 9/10 = 90% |
| Holdout recall | 2/3 = 66.7% |
| Observed control false-positive rate | 0/3 = 0% |

The deliberately small nine-port attack accounts for the miss. All nine attacks with at least 10 distinct rejected ports within 5 minutes were detected in this dataset, including two distinct slower cases. The all-trials recall includes development and tuning captures; it must not be described as independent test accuracy. Only the three holdout attack captures were newly generated after threshold selection. The study has no independent holdout benign capture after tuning, only previously collected controls replayed with the tuned detector. The modest number of control scenarios cannot establish a production false-positive rate.

## 11. Limitations, holdbacks and reasoning

| Limitation / holdback | Why it matters | Possible future extension (not implemented) |
|---|---|---|
| **Below-threshold scans** (demonstrated) | Nine rejected ports did not alert; targeted scans may use just a few ports. | Separate sensitive-port, rare-port or cross-event indicators; tune with richer data. |
| Very slow scans beyond five minutes | Probes may age out before ten accumulate. A larger window can also increase state usage and false positives. | Multi-scale windows; baseline across representative activity. |
| Open-only or mixed scans with fewer than ten rejections | Successful service connections are deliberately excluded; an effective scan may discover services without rejection. | Complement with distinct-all-ports and service-context detection; use rejection evidence for confidence. |
| Silently filtered ports or unobserved replies | The event requires a rejection. A dropped SYN may yield no response rather than `REJ`. | Use distinct failed/unanswered probes and firewall telemetry; validate timeout handling separately. |
| Horizontal/distributed scanning | Source-destination grouping isolates one pair; probing many targets at one port or distributing probes across sources can remain below the per-pair threshold. | Separate address-sweep detector; enrich with asset and temporal relationships. |
| UDP and other TCP scan modes | Tested `-sT` and shell TCP connections; non-connect scan techniques can produce different packet/response patterns. | Validate SYN, UDP and other modes separately; do not claim coverage from this test suite. |
| Authorized scans and operational diagnostics | A legitimate scanner can legitimately contact many closed ports; detector observes behavior, not intent. | Use scoped scanner identity, target scope, expected schedule and change tickets. Avoid blanket exemptions. |
| Limited normal diversity | Only three open victim services (SSH, HTTP, SMB) and two focused controls plus one 10-min capture; high-cardinality normal traffic was not represented. | Collect hours/days of varied enterprise flows and legitimate multi-service health checks. |
| Threshold tuning on six scenarios | 10 was selected on these scenarios; may overfit a small lab. Several cases were tried only once. | Repeat varied tests on other hosts, ports, loads and negative scenarios. A holdout benign set is needed. |
| Sensor placement and capture quality | Victim-local capture sees only its traffic; asymmetric capture or packet loss can prevent rejection observations. `-C` was a lab workaround for offload artifacts. | Capture at an appropriate network monitoring point; validate bidirectional capture and packet loss. |
| Suppression and state scaling | A five-minute notice suppression may hide a second distinct scan on the same pair; per-pair tables require memory and pruning. No throughput benchmark or continuous mixed-load test was performed. | Benchmark memory/load; emit updates when intensity changes, and use incident-aware suppression. |

The strongest immediate limitation is that rejection-based coverage is not comprehensive. The strongest evaluation limitation is limited benign diversity. We retain the detection scope honestly and prioritize completing the other required detectors. Additional variants are justified by actual gaps, not by adding complexity for its own sake.

## 12. ATT&CK mapping and conclusion

T1046 — Network Service Discovery. Our detector identifies evidence of repeated probing of different rejected TCP ports on one victim. It does not detect all T1046 behavior and does not establish malicious intent. The rule is suitable as an early-stage alert for later incident correlation with independently observed SSH authentication failures, SMB share access or other activity against the same service/asset. That correlation layer is not part of this detector or this validation.

The project uses research-backed defaults, interpretable protocol events, empirical feature comparison, controlled threshold tuning, a separate holdout and a demonstrated evasion. The final recommended lab configuration is `scan-tuned.zeek` (10 rejected ports in a rolling five-minute window). The experiment supports its selection for this lab, while identifying specific improvements needed for operational deployment.

## References

1. Zeek v6.0.9, [Historical TCP scan detection policy, `policy/misc/scan.zeek`](https://docs.zeek.org/en/v6.0.9/scripts/policy/misc/scan.zeek.html).
2. Zeek, [TCP analyzer events (`connection_rejected`)](https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_TCP.events.bif.zeek.html) and [connection log definitions](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).
3. MITRE ATT&CK, [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/).
4. MITRE ATT&CK, [DET0376 — Behavioral Detection Strategy for Network Service Discovery Across Platforms](https://attack.mitre.org/detectionstrategies/DET0376/).
5. Elastic Security, [Potential Network Scan Detected](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/network/discovery_potential_port_scan_detected).
6. Elastic Security, [Threshold rules — port scan detection with cardinality constraint](https://www.elastic.co/docs/solutions/security/detect-and-alert/threshold).
7. Nmap, [TCP Connect Scan (`-sT`)](https://nmap.org/book/scan-methods-connect-scan.html).
8. Nmap, [Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html) and [Port Scanning Basics](https://nmap.org/book/man-port-scanning-basics.html).
9. Zeek, [Scripting declarations and redefinitions](https://docs.zeek.org/en/current/reference/zeekscript/statements.html).

External references motivate design; the local terminal transcripts and PCAP-derived results are the primary evidence for the reported experimental counts.
