# Tripwire — HTTP Wordlist Scanning Detection

**Technique:** MITRE ATT&CK T1595.003 — Active Scanning: Wordlist Scanning  
**Final detector:** `rules/http-contextual.zeek`  
**Configuration:** 50 HTTP 403/404 GET responses, 25 distinct normalized failing paths, error ratio ≥ 0.50, within a rolling five-minute window  
**Environment:** isolated Docker lab, Zeek 9.0.1, Nginx, FFUF 2.3.0, curl  
**Experimental date:** 21 November 2026

## 1. Objective and threat model

HTTP wordlist scanning attempts to identify undisclosed or poorly protected web resources by systematically requesting candidate paths. Finding a valid resource may enable later exploitation or unauthorized access. Our detector identifies patterns of unsuccessful directory and file discovery, rather than attempting to detect a particular tool or prove that exploitation succeeded.

The victim (`172.30.77.10`) serves HTTP on TCP 80. The attacker (`172.30.77.20`) and normal client (`172.30.77.30`) generate both scanning and control traffic; the management host is `.40`. All tests target the team's isolated lab. The rule does not contain an attacker IP, tool name, or fixed response-body signature. Indeed, a scanning experiment initiated from the ordinary client is correctly detected.

## 2. Research, hypotheses and design rationale

| Source | Relevant finding | Our decision |
|---|---|---|
| MITRE ATT&CK T1595.003 and DET0868 [1,2] | Wordlist discovery involves repeated probing; concentrated suspicious network activity is a detection signal. | Aggregate activity by origin and destination service; use ATT&CK metadata. |
| Elastic Security prebuilt web discovery rule [3] | Detects GET responses with 403/404, using both volume and distinct URL counts. The published rule requires more than 500 errors and 250 distinct URLs, executes every 10 minutes and searches an 11-minute lookback. | Adapt the two-feature detection pattern, rather than transferring enterprise thresholds unchanged. |
| Elastic Security Labs, 8 May 2026 [4] | A smaller homelab deployment lowered these thresholds to `>100` errors and `>50` distinct URLs. | Start with the lab's inclusive 100/50 candidate, then compare lower values empirically. |
| Elastic's investigation guidance [3] | Legitimate crawlers, faulty deployments and shared proxies can produce large volumes of failed requests. | Test a broken application explicitly; investigate whether response-code distribution helps. |
| Zeek 9.0.1 HTTP analyzer [5,6] | HTTP logs describe transactions, including optional method, URI and status code, connection UID and transaction depth. | Operate on parsed HTTP transactions, guard optional fields, deduplicate by UID and transaction depth. |

The final 50/25/50% configuration is a *lab-calibrated engineering choice*. Neither Elastic nor MITRE prescribes it. The five-minute rolling window is an implementation choice for this lab, distinct from Elastic's scheduled polling window. There is no claim that these thresholds are optimal for production traffic.

| Hypothesis | Experimental method |
|---|---|
| H1: Error volume alone is enough. | Compare fuzzing to 120 repeated requests for one absent asset. |
| H2: Distinct raw URLs improve detection. | Compare wordlists to requests with different query values for one path. |
| H3: Distinct normalized failing paths reduce false positives. | Remove query strings; test repeated errors and changing query parameters. |
| H4: Error-body size or user-agent can identify the tool. | Compare failing-response sizes across benign and attack captures; run FFUF with a browser-like user-agent. |
| H5: Lower count thresholds improve small-scan coverage. | Compare original 100/50 and tuned 50/25 on 150-, 60- and 50-path wordlists. |
| H6: The error ratio helps distinguish scanning from mixed legitimate traffic. | Compare an intentionally broken-application simulation with a deliberately padded scan. |
| H7: Thresholds are enforced independently and inclusively. | Generate 49 errors, then 50 errors covering 24 or 25 distinct paths. |

## 3. Visibility validation and feature selection

We initially ran URL requests with curl and a five-entry FFUF wordlist (`admin`, `backup`, `login`, `config`, `nonexistent`). Zeek produced HTTP log records containing source/destination addresses, request method, URI, status code, response body length and user agent. An ordinary request to `/` produced a 200 response and a 29-byte body. Requests for unavailable resources produced 404 responses of 153 bytes.

Example observed fields (selected from `logs/visibility-corrected/http.log`):

| Source | Method | URI | Status | Response bytes | User agent |
|---|---|---|---:|---:|---|
| `.30` | GET | `/` | 200 | 29 | `curl/8.22.0` |
| `.20` | GET | `/nonexistent` | 404 | 153 | `curl/8.22.0` |
| `.20` | GET | `/login` | 404 | 153 | `Fuzz Faster U Fool v2.3.0` |
| `.20` | GET | `/backup` | 404 | 153 | `Fuzz Faster U Fool v2.3.0` |

The 153-byte body was a property of this web server's error response, not a reliable attack signature. Every error in the later attack and control captures also had a 153-byte body. Fuzzing was further tested using a generic browser-like user-agent, which prevents a tool-name-only rule from being sufficient. Our detector deliberately does not use either field as a mandatory condition.

| Field or derived feature | Purpose |
|---|---|
| `id.orig_h`, `id.resp_h`, `id.resp_p` | Group by source and destination service. The same host can generate legitimate and malicious traffic. |
| `method` | Restrict this particular analytic to GET-based directory scanning. |
| `status_code` | Count denied/missing resources (403 and 404), not all traffic indiscriminately. |
| `uri` | Derive path diversity; strip the query beginning with `?` so retries with distinct query values are not mistaken for multiple resources. |
| `uid`, `trans_depth` | Identify an HTTP transaction even when one TCP connection carries many requests. |
| `network_time()` | Track observations across a sliding five-minute window during replay or network analysis. |
| Error ratio | Divide observed 403/404 GET responses by all observed GET responses having required fields in the same group and window. |

## 4. Experiment generation and ground truth

Each named capture is a separately generated traffic scenario. The existing `run_scan_test` helper (documented in the Port Scan report) starts victim-side tcpdump, invokes the traffic generator and stops capture. Packet captures are analyzed offline with Zeek and `-C` because the initial capture demonstrated checksum offloading artifacts.

### 4.1 Wordlist and negative controls

Representative reproduction commands (run only in the isolated lab):

```bash
run_scan_test http-ffuf150 docker compose exec -T attacker sh -c '
    seq 1 150 | sed "s/^/lab-path-/" > /tmp/web-list.txt
    ffuf -w /tmp/web-list.txt -u http://victim/FUZZ \
        -mc all -rate 30 -t 10 -H "User-Agent: Mozilla/5.0" -s'

run_scan_test http-ffuf60 docker compose exec -T attacker sh -c '
    seq 1 60 | sed "s/^/small-path-/" > /tmp/small-list.txt
    ffuf -w /tmp/small-list.txt -u http://victim/FUZZ \
        -mc all -rate 30 -t 10 -H "User-Agent: Mozilla/5.0" -s'

run_scan_test http-ffuf50 docker compose exec -T client sh -c '
    seq 1 50 | sed "s/^/fresh-path-/" > /tmp/web-fresh.txt
    ffuf -w /tmp/web-fresh.txt -u http://victim/FUZZ \
        -mc all -rate 30 -t 10 -H "User-Agent: Mozilla/5.0" -s'

run_scan_test http-repeated docker compose exec -T client sh -c '
    for i in $(seq 1 120); do
        curl -s -o /dev/null http://victim/missing-image.png
    done'

run_scan_test http-query docker compose exec -T client sh -c '
    for i in $(seq 1 120); do
        curl -s -o /dev/null "http://victim/missing-image.png?id=$i"
    done'

run_scan_test http-normal docker compose exec -T client sh -c '
    for i in $(seq 1 120); do
        curl -s -o /dev/null http://victim/
    done'
```

The original 10-minute benign capture (`benign.pcap`) contains 20 normal GETs and five requests for the same missing image. The initial mixed visibility capture contains six failing GETs covering five distinct paths from the attacker and one successful GET from the client.

### 4.2 Broken application versus padded scanning

We deliberately generated two sequences with the same proportions of successful and failed requests. The first models an application requesting missing assets; the second models a wordlist probe interleaved with successful requests. Neither is an uncontrolled real-world dataset.

```bash
run_scan_test http-broken-app docker compose exec -T client sh -c '
    for i in $(seq 1 60); do
        curl -s -o /dev/null http://victim/
        curl -s -o /dev/null http://victim/
        curl -s -o /dev/null "http://victim/missing-asset-$i.png"
    done'

run_scan_test http-padded-scan docker compose exec -T attacker sh -c '
    for i in $(seq 1 60); do
        curl -s -o /dev/null http://victim/
        curl -s -o /dev/null http://victim/
        curl -s -o /dev/null "http://victim/probe-path-$i"
    done'
```

### 4.3 Measured features

The following values come from the user's Python analysis of actual Zeek `http.log` outputs, saved in `evidence/http-feature-comparison.txt`. These are capture-wide per-source summaries, not the rule's exact rolling-window alert calculation.

| Capture | Ground truth | GETs | 403/404 | Raw failing URLs | Normalized failing paths | Error ratio |
|---|---|---:|---:|---:|---:|---:|
| `http-ffuf150` | Attack | 150 | 150 | 150 | 150 | 1.000 |
| `http-ffuf60` | Attack | 60 | 60 | 60 | 60 | 1.000 |
| `http-ffuf50` | Attack from client | 50 | 50 | 50 | 50 | 1.000 |
| `http-repeated` | Benign | 120 | 120 | 1 | 1 | 1.000 |
| `http-query` | Benign | 120 | 120 | 120 | 1 | 1.000 |
| `http-normal` | Benign | 120 | 0 | 0 | 0 | 0.000 |
| `http-broken-app` | Benign simulation | 180 | 60 | 60 | 60 | 0.333 |
| `http-padded-scan` | Attack simulation | 180 | 60 | 60 | 60 | 0.333 |
| `benign` | Normal baseline | 25 | 5 | 1 | 1 | 0.200 |
| `visibility` (attacker) | Small attack | 6 | 6 | 5 | 5 | 1.000 |

The extra successful client GET in `visibility` is not mixed into the attacker's features. All recorded errors in the above table had a 153-byte body.

**Key finding:** the broken-application and padded-scan scenarios are indistinguishable by these aggregate features. Their exact paths and source addresses differ, but relying on the known attacker address or synthetic filename prefix would overfit the experiment. The error ratio can suppress both; it cannot determine which represents malicious intent.

## 5. Candidate-rule comparison and threshold selection

| Candidate | Logic | Attack scenarios alerted / 5 | Benign scenarios alerted / 5 |
|---|---|---:|---:|
| A | ≥50 errors | 4 | 3 |
| B | ≥50 distinct raw failing URLs | 4 | 2 |
| C | ≥100 errors and ≥50 normalized paths | 1 | 0 |
| C2 | ≥50 errors and ≥25 normalized paths | 4 | 1 |
| D | C2 and error ratio ≥0.50 | 3 | 0 |

The comparison above is based on the feature summaries for A–D. Candidate C was executed on the original subset, and the subsequent C2 and D comparison was actually executed in Zeek on all ten scenarios (Section 7). A and B were evaluated computationally, not deployed as Zeek notice rules.

Rationale:

- **50 errors:** the 100-error candidate missed the known 50- and 60-path scans. Reducing the count captures those scenarios at the cost of more sensitivity to faulty applications.
- **25 normalized paths:** a diversity requirement separates retries and changing query values from a sweep across unrelated paths. The 25 threshold is a practical candidate that allows repeated requests among 50 failures; the experiments establish the exact boundary, not that 25 is universally optimal.
- **50% error ratio:** 0.50 separates the observed 100%-error FFUF captures from the 33.3%-error broken-application capture. Many values between one-third and one would also separate these particular cases. We choose the interpretable majority-error condition, acknowledging the padded-scan miss. It is not a research-prescribed cutoff.
- **Five minutes:** a configurable observation window balances aggregation of slower activity with the risk of accumulating unrelated requests. No independent HTTP window-length sweep or expiry-boundary experiment was performed; the fast scans fit both short and long windows.

The final conservative detector prioritizes the hackathon's low false-positive requirement. The no-ratio variant is retained as a sensitivity alternative and a potential source of weaker evidence for future incident correlation.

## 6. Implemented Zeek rule

Final file: `rules/http-contextual.zeek`.

```zeek
@load base/frameworks/notice
@load base/protocols/http

module Tripwire;

export {
    redef enum Notice::Type += { HTTP_Fuzzing };
    option http_error_threshold: count = 50;
    option http_path_threshold: count = 25;
    option http_min_error_ratio: double = 0.5;
    option http_window: interval = 5min;
}

# MITRE ATT&CK: T1595.003 - Wordlist Scanning

type HTTPObservation: record {
    ts: time;
    path: string;
    is_error: bool;
};

global http_activity:
    table[addr, addr, port] of table[string] of HTTPObservation
    &write_expire=1hr;

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

    if ( errors >= http_error_threshold &&
         |unique_paths| >= http_path_threshold &&
         ratio >= http_min_error_ratio )
        {
        NOTICE([
            $note=HTTP_Fuzzing, $uid=rec$uid, $id=rec$id,
            $src=src, $dst=dst, $p=dest_port,
            $msg=fmt(
                "T1595.003: %d errors, %d distinct paths, %d GET requests, error ratio %.2f within %s",
                errors, |unique_paths|, |recent|, ratio, http_window),
            $identifier=fmt("%s:%s:%s", src, dst, dest_port),
            $suppress_for=http_window
        ]);
        }
    }
```

The alternative `rules/http-no-ratio.zeek` reuses the exact same implementation:

```zeek
@load ./http-contextual
redef Tripwire::http_min_error_ratio = 0.0;
```

The original `rules/http-detection.zeek` used 100 errors and 50 normalized paths and did not track all GET outcomes for the ratio. Load only the chosen variant (final or alternate), not the original and final together: these files declare overlapping notice and option names.

### 6.1 Logic and state management

For each HTTP transaction with the required fields, record the path and whether its response is a 403/404. Remove observations older than the configured window, recompute the error count and failing-path set, and divide by the number of retained GET transactions. When all three conditions are satisfied, emit a structured Zeek notice containing the attack mapping and causal feature counts. Notice suppression prevents repeated alerts for the same source/destination service during the next five minutes; it does not mean subsequent requests were absent.

## 7. Actual Zeek replay results

Both rule variants were replayed against the same ten captures. Separate output directories preserve the evidence. No code changes were introduced between those two variants other than `http_min_error_ratio`.

```bash
for rule in http-contextual http-no-ratio; do
    for capture in http-ffuf150 http-ffuf60 http-ffuf50 \
        http-repeated http-query http-normal http-broken-app \
        http-padded-scan benign visibility; do
        folder="logs/$rule-$capture"
        mkdir -p "$folder"
        docker run --rm --network none \
            -v "$PWD/captures:/pcaps:ro" \
            -v "$PWD/rules:/rules:ro" \
            -v "$PWD/$folder:/out" -w /out \
            --entrypoint zeek zeek/zeek:latest \
            -C -r "/pcaps/$capture.pcap" \
            "/rules/$rule.zeek" LogAscii::use_json=T
        if [ -f "$folder/notice.log" ]; then
            cat "$folder/notice.log"
        else
            echo "No alerts"
        fi
    done
done
```

| Scenario | Original 100/50 | Actual 50/25, no ratio | Actual 50/25 + ratio (final) |
|---|---|---|---|
| FFUF 150 | Alert | Alert | Alert |
| FFUF 60 | No alert | Alert | Alert |
| FFUF 50 (client) | Not replayed with original in supplied output | Alert | Alert |
| Repeated error | No alert | No alert | No alert |
| Query-string variation | No alert | No alert | No alert |
| Normal burst | No alert | No alert | No alert |
| Broken application | Not replayed with original in supplied output | Alert (FP) | No alert |
| Padded scan | Not replayed with original in supplied output | Alert | No alert (FN) |
| Normal baseline | No alert | No alert | No alert |
| Five-path visibility test | No alert | No alert | No alert (FN) |

Example actual final notice (50-path test from ordinary client; selected fields):

```json
{"ts":1795241581.599349,"uid":"ClynQpBCq94NWcBg","src":"172.30.77.30","dst":"172.30.77.10","p":80,"note":"Tripwire::HTTP_Fuzzing","msg":"T1595.003: 50 errors, 50 distinct paths, 50 GET requests, error ratio 1.00 within 5.0 mins","suppress_for":300.0}
```

The no-ratio alternative emitted notices for both the broken-application and padded-scan captures after 150 observed GETs: 50 errors, 50 distinct failing paths, ratio 0.33. The final ratio rule generated no notices for either. Alert-time counts differ from full-capture totals (60 errors and 180 GETs), showing that the detector triggers when its threshold is reached rather than waiting until the entire capture ends.

### 7.1 Scenario-level metrics

| Metric | No-ratio variant | Final ratio variant |
|---|---:|---:|
| True positives | 4 | 3 |
| False negatives | 1 | 2 |
| True negatives | 4 | 5 |
| False positives | 1 | 0 |
| Recall (TP / all attacks) | 80% | 60% |
| False-positive rate (FP / all benign) | 20% | 0% |
| Precision (TP / all alerted scenarios) | 80% | 100% |
| Accuracy (correct scenarios / 10) | 80% | 80% |

For the three full wordlist scans (50, 60 and 150 paths), the final detector alerted in all three cases. Its 60% overall recall explicitly includes the two challenging cases (five-path and padded scan), which prevents inflated claims. The two variants have equal scenario-level accuracy on this small dataset, illustrating why accuracy alone does not resolve the detector-design trade-off.

These are scenario-level results, not packet-level classification or a representative production measurement. One capture per named scenario was used; replaying it with two rules does not create two independent traffic trials. The extra boundary probes below are reported separately as implementation-verification cases, not added to the confusion matrix. The normal baseline includes 25 GETs but constitutes one capture-level negative scenario. No independent, representative production holdout exists; the same small lab informed tuning and evaluation.

## 8. Independent boundary validation

Three fresh captures were generated after selecting the final candidate. All tests ran from the ordinary client. The second and third probes vary path diversity while holding error count constant.

```bash
{
    run_scan_test http-boundary49 docker compose exec -T client sh -c '
        for i in $(seq 1 49); do
            curl -s -o /dev/null "http://victim/test-$i"
        done'
    run_scan_test http-boundary24paths docker compose exec -T client sh -c '
        for i in $(seq 1 50); do
            p=$(( (i - 1) % 24 + 1 ))
            curl -s -o /dev/null "http://victim/test-$p"
        done'
    run_scan_test http-boundary25paths docker compose exec -T client sh -c '
        for i in $(seq 1 50); do
            p=$(( (i - 1) % 25 + 1 ))
            curl -s -o /dev/null "http://victim/test-$p"
        done'
} 2>&1 | tee evidence/http-boundary-tests.txt
```

Replay each capture using the final rule, substituting its name into the command in Section 7. The supplied replay results were:

| Capture | Requested errors | Requested distinct paths | Packets captured | Expected notice | Actual | Result |
|---|---:|---:|---:|---|---|---|
| `http-boundary49` | 49 | 49 | 490 | No | No | PASS |
| `http-boundary24paths` | 50 | 24 | 500 | No | No | PASS |
| `http-boundary25paths` | 50 | 25 | 500 | Yes | Yes | PASS |

All three captures reported zero kernel packet drops, and their traffic commands exited successfully. One generated capture per boundary, with one final-rule replay each. For the two negative cases the counts follow from the generator; the positive notice independently confirms its exact thresholds. The 50% ratio boundary and five-minute time boundary were not independently tested.

Actual boundary notice message:

```text
T1595.003: 50 errors, 25 distinct paths, 50 GET requests, error ratio 1.00 within 5.0 mins
```

## 9. Limitations, evasion and future production adaptation

| Limitation | Evidence or reasoning | Improvement (not implemented) |
|---|---|---|
| Small scans below thresholds | Initial five-path fuzzing and 49-request boundary do not alert. | Tune per service using a representative baseline; use other correlated indicators. |
| Mixed successful and failed traffic | Padded scan ratio 0.33 evaded final rule. Lowering the ratio also alerts on the synthetic broken app. | Preserve weak-signal evidence for contextual correlation with other independently observed security events. |
| Benign high-diversity failures | Even the ratio rule could alert on a crawler generating >50% failures. | Approved scanner inventory, change-management context, reverse-proxy/application logs and analyst triage. |
| HTTPS visibility | Passive Zeek cannot inspect encrypted application paths/status codes without access to plaintext. | Collect logs from trusted TLS termination or application/reverse-proxy telemetry. |
| Method/status scope | Only GET and 403/404 count. Successful probes, soft 404s returning 200, 401s, redirects, and other methods can go undetected. | Design separate analytics for those behaviors, based on application semantics and logs. |
| Query normalization trade-off | Removing queries prevents misleading path counts but loses signal for parameter fuzzing. | Separate parameter-fuzzing detector and retain original URI for investigation. No complete URL canonicalization is attempted. |
| Shared IPs and virtual hosts | A source IP can represent multiple clients, and the same target IP/port can host multiple sites. | Use verified proxy identity and HTTP host/site context where available; avoid trusting arbitrary forwarded headers. |
| Distributed or slow probes | Per-source and rolling-window aggregation may miss activity split across sources or extending beyond the window. | Longer-horizon or cross-source analytics; validate effect on alert noise. |
| State and throughput | The script keeps transaction records and recomputes sets per incoming GET; cost grows with window traffic. State expiry and notice suppression do not guarantee production scalability. | Profile resource usage and adopt bounded state, incremental counters, or SIEM aggregation in higher-volume deployments. |
| Capture and timing limitations | Replay depends on capture coverage, parser visibility and transaction completion; open or incomplete transactions may not contribute. | Validate live deployment, monitor packet loss, and compare with authoritative access logs. |

## 10. Implications for incident correlation

The experiment provides a concrete reason for combining independent signals: a standalone HTTP rule must trade coverage against false-positive risk when benign and malicious traffic share the same aggregate features.

For example, the no-ratio variant could provide a weaker signal associated with a source and target service. If that source also shows independent evidence of port discovery, password guessing or unexpected SMB administrative-share access within a relevant time window, the combined evidence may justify increased investigative priority. A source-IP match alone does not prove identity or malicious intent; destination relationships, event timing, independent technique evidence and outcomes should inform grouping. Correlation is a proposed extension, not a measured result in this report. An isolated broken application should not be automatically classified as an incident.

## 11. MITRE mapping and evidence manifest

- **Tactic:** Reconnaissance (TA0043).
- **Technique/sub-technique:** Active Scanning / Wordlist Scanning (T1595.003).
- **Detection strategy:** DET0868, analytics AN2000; network traffic content (DC0085) [2].
- **Coverage qualification:** T1595.003 is formally reconnaissance. Our internal lab simulates the observable wordlist behavior and follows that mapping; real post-compromise internal discovery may warrant other contextual ATT&CK mappings. A notice does not prove exploitation or successful access.
- **Final notice:** `Tripwire::HTTP_Fuzzing`.

| Artifact | Purpose |
|---|---|
| `rules/http-detection.zeek` | Original 100/50 candidate |
| `rules/http-contextual.zeek` | Final detector |
| `rules/http-no-ratio.zeek` | Alternate sensitivity configuration |
| `captures/http-*.pcap` | Individual attack/control/boundary captures |
| `captures/benign.pcap`, `captures/visibility.pcap` | Shared normal baseline and initial visibility check |
| `evidence/http-validation-traffic.txt`, `evidence/http-extra-tests.txt` | Traffic generation records |
| `evidence/http-feature-comparison.txt` | Measured feature values and retrospective candidate results |
| `evidence/http-boundary-tests.txt` | Boundary traffic and capture evidence |
| `logs/detect-<capture>-http/http.log` | Structured HTTP transaction evidence from original replays |
| `logs/http-contextual-<capture>/` | Final actual replay output, including `notice.log` when generated |
| `logs/http-no-ratio-<capture>/` | Alternative actual replay output |

**Conclusion:** The final detector is explainable, research-informed and empirically calibrated. It detects the three intended full wordlist scans, emits no notices in five negative scenarios, and passes all three independent threshold-implementation checks. Its two known misses are retained as evidence of the limits of a narrow high-confidence detector; no claim of universal accuracy is made.

## References

1. MITRE ATT&CK, [T1595.003 — Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/).
2. MITRE ATT&CK, [DET0868 — Detection of Wordlist Scanning](https://attack.mitre.org/detectionstrategies/DET0868/).
3. Elastic Security, [Web Server Discovery or Fuzzing Activity — prebuilt detection rule](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/cross-platform/reconnaissance_web_server_discovery_or_fuzzing_activity).
4. Erik-Jan de Kruijf, Elastic Security Labs, 8 May 2026, [Detecting Web Server Probing & Fuzzing in Traefik with Automated Cloudflare Response](https://www.elastic.co/security-labs/blog/detecting-web-server-probing-and-fuzzing).
5. Zeek 9.0.1, [HTTP protocol script documentation](https://docs.zeek.org/en/v9.0.1/scripts/base/protocols/http/main.zeek.html).
6. Zeek 9.0.1, [Protocol analyzers](https://docs.zeek.org/en/v9.0.1/reference/zeekscript/proto-analyzers.html).
