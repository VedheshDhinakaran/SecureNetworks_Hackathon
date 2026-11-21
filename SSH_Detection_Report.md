# Tripwire — SSH Password Guessing Detection

**Technique:** MITRE ATT&CK T1110.001 — Brute Force: Password Guessing  
**Detector:** `rules/ssh-detection.zeek`  
**Configuration:** 8 inferred authentication attempts in failed sessions within a rolling 2-minute window  
**Environment:** isolated Docker lab, Zeek 9.0.1, OpenSSH server, Hydra and `sshpass`  
**Experimental date:** 21 November 2026

## 1. Objective

SSH password guessing involves repeated attempts to authenticate with incorrect credentials in an effort to gain access. A useful detector should recognize multiple attempts within the same SSH connection as well as multiple failed connections, while avoiding alerts for ordinary logins and occasional typographical errors.

SSH encrypts its authentication exchange. A network sensor cannot directly read the submitted username, password or definitive authentication messages from normal encrypted SSH traffic. Zeek estimates authentication outcomes and counts from observable packet characteristics. Therefore, the primary design question is not just choosing a threshold, but deciding **which quantity is actually observable and how reliable it is**.

The lab victim `172.30.77.10` provides SSH on TCP 22. The attack container is `172.30.77.20`; the normal client is `172.30.77.30`. All traffic was generated against our isolated service and dummy lab account `labuser`. The detector does not hard-code the attacker IP.

## 2. Research and hypotheses

| Source | Relevant finding | Design decision |
|---|---|---|
| MITRE T1110.001 and DET0551 [1,2] | Repeated authentication failures are indicators of password guessing; subsequent successful authentication can add context. | Detect a burst of failed authentication evidence; preserve the possibility of later correlation. |
| Zeek SSH analyzer and log documentation [3,4] | Authentication results and attempts are inferred from packet sizes; unknown results are possible. The final `ssh_auth_result` event is raised once per connection. | Do not count unknown results as failures. Use the inferred attempts associated with a known failed outcome. |
| Zeek built-in SSH brute-force policy [5] | Default is 30 failed SSH connections over 30 minutes; successful login by a previous guesser is a separate notice. | Compare failed-connection counts against a weighted attempt count. Do not equate the built-in policy's measurement with individual password guesses. |
| Wazuh rule testing documentation [6] | Example rule 5712 triggers after eight failed logins for nonexistent users from one source in two minutes, measured from endpoint logs. | Adapt 8/2 min as a candidate; independently validate because our network-derived attempt count is different and the lab account exists. |

The 8/2-minute configuration is research-inspired, not a direct reproduction of Wazuh rule 5712. It is not a universally optimal security threshold. We compare neighboring thresholds (5 and 12) to understand the sensitivity trade-off.

| Hypothesis | Reasoning | Experimental test |
|---|---|---|
| H1: total SSH sessions are sufficient. | Repeated connections may indicate guessing. | Compare Hydra and a burst of 12 legitimate successful logins. |
| H2: failed SSH sessions are a stronger indicator. | Successes are not suspicious solely because of volume. | Compare the number of failed sessions to the actual number of password failures. |
| H3: weight failed sessions by inferred authentication attempts. | Attack tools may reuse connections for multiple guesses. | Match Zeek and server records by source IP and port, then test Hydra. |
| H4: one or two errors should not trigger a brute-force alert. | Normal users can mistype passwords. | Two failures followed by three successes and the 10-minute benign capture. |
| H5: eight inferred attempts within two minutes detects the intended attack episodes. | Candidate combines count and timing. | Seven/eight-attempt boundaries and a slower eight-attempt sequence. |
| H6: a successful login after many failures is additional evidence. | Possible credential compromise, but ordinary retries can also precede success. | Eight failed logins followed by a successful login versus the benign two-failure control. This was observed as a scenario, not implemented as a second correlation rule. |

## 3. Visibility validation: server logs versus network inference

An initial single incorrect-password attempt and a successful normal login were visible in `ssh.log`. Both outcomes were independently confirmed using SSH server logs. A more realistic Hydra attack was then generated to test connection reuse.

### 3.1 Attack generation

```bash
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_scan_test ssh-hydra \
    docker compose exec -T attacker sh -c '
    for i in $(seq 1 12); do
        printf "WrongLabPass%02d\n" "$i"
    done > /tmp/ssh-test-passwords.txt
    hydra -l labuser -P /tmp/ssh-test-passwords.txt -t 2 ssh://victim
' 2>&1 | tee evidence/ssh-hydra-traffic.txt
```

The `run_scan_test` helper starts `tcpdump` on the victim, executes the supplied command, stops capture and records the output (see Port Scan report). The wordlist contained 12 deliberately incorrect dummy passwords, but the server recorded 14 failures; a tool's wordlist length is not an authoritative count of actual authentication events.

For the benign retry control, five separate SSH connections were initiated from `client`, using two incorrect passwords followed by three correct passwords. Each connection was configured for password authentication and one password prompt:

```bash
run_scan_test ssh-control docker compose exec -T client bash -c '
    for pw in WrongPassword WrongPassword LabUser123 LabUser123 LabUser123; do
        sshpass -p "$pw" ssh \
          -o StrictHostKeyChecking=no \
          -o PreferredAuthentications=password \
          -o PubkeyAuthentication=no \
          -o NumberOfPasswordPrompts=1 \
          labuser@victim "echo Normal login"
        echo "Exit code: $?"
    done
' 2>&1 | tee evidence/ssh-control-traffic.txt

docker compose logs --no-color --timestamps --since "$start" victim \
    > evidence/ssh-server-ground-truth.txt
grep -E 'Failed password|Accepted password' evidence/ssh-server-ground-truth.txt
```

The `StrictHostKeyChecking=no` setting is a convenience for this disposable lab only, not a recommended production SSH policy.

### 3.2 Actual matched results

We joined the server evidence and Zeek observations using the source IP and ephemeral source port (one target and a short capture interval). In a wider deployment, match full connection identity and time to avoid ambiguity from source-port reuse or NAT. Zeek UIDs are replay-local and should not be joined across separate replays.

| Originator port | SSH server: failed passwords | Zeek final `auth_success` | Zeek `auth_attempts` |
|---:|---:|---|---:|
| 45856 | 6 | false | 5 |
| 45858 | 6 | false | 5 |
| 40844 | 1 | false | 1 |
| 40850 | 1 | false | 1 |
| 45842 | 0 observed | missing | 0 |
| **Total** | **14** | **4 inferred failed sessions, 1 unknown** | **12** |

Representative server evidence:

```text
2026-11-21T05:57:14.400476304Z Failed password for labuser from 172.30.77.20 port 45856 ssh2
2026-11-21T05:57:30.218843354Z Failed password for labuser from 172.30.77.20 port 45856 ssh2
2026-11-21T05:57:32.186863572Z Failed password for labuser from 172.30.77.20 port 40844 ssh2
```

Representative Zeek field values for port 45856: `auth_success=false`, `auth_attempts=5`, `compression_alg=none`. All five attack session records negotiated `compression_alg=none`.

Key findings:

- Hydra reused two connections for six password failures each. Therefore, a threshold of eight failed sessions would miss the observed attack even though the server recorded 14 failed passwords.
- Zeek inferred 12 attempts associated with the four failed sessions. The two-attempt undercount is an observed measurement difference (12/14 ≈ 85.7% count ratio), not a general accuracy rate or evidence that individual guesses were uniquely matched. We did not establish the precise cause of each missing inferred attempt.
- The fifth SSH session had no inferred authentication result (missing field, zero attempts). It was not interpreted as a failed password or successful login.
- The two failed and three successful benign logins were all correctly represented at the session level; each had one inferred attempt.

These findings motivate summing attempts in sessions where Zeek has inferred a final failure. They also motivate preserving endpoint logs for investigation. Zeek's `auth_attempts` is an estimate of authentication activity, not a decrypted password counter. In particular, combined public-key/password authentication and other multifactor mechanisms may yield multiple legitimate authentication stages.

## 4. Final Zeek rule

Use a rolling window over **final failed-session observations** grouped by `(source IP, destination IP)`. Each distinct connection UID contributes its inferred attempt count once. A session whose final outcome is successful contributes zero, so ordinary successful logins and successful multi-stage authentication do not themselves inflate the failure count. Unknown outcomes contribute zero as the final-result event is not raised. The trade-off is that failed attempts inside an eventually successful connection are not counted by this rule.

`rules/ssh-detection.zeek`:

```zeek
@load base/frameworks/notice
@load base/protocols/ssh

module Tripwire;

export {
    redef enum Notice::Type += { SSH_Brute_Force };
    option ssh_threshold: count = 8;
    option ssh_window: interval = 2min;
}

# MITRE ATT&CK: T1110.001 - Password Guessing
type FailedSession: record {
    ts: time;
    attempts: count;
};

global ssh_failures: table[addr, addr] of
    table[string] of FailedSession &write_expire=1hr;

event ssh_auth_result(c: connection, result: bool,
                      auth_attempts: count)
    {
    if (result || auth_attempts == 0)
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local now = network_time();
    local recent: table[string] of FailedSession = table();

    if ([src, dst] in ssh_failures)
        recent = ssh_failures[src, dst];

    local stale: set[string] = set();
    for (uid in recent)
        {
        if (now - recent[uid]$ts > ssh_window)
            add stale[uid];
        }
    for (old_uid in stale)
        delete recent[old_uid];

    recent[c$uid] = [$ts=now, $attempts=auth_attempts];
    ssh_failures[src, dst] = recent;

    local total: count = 0;
    for (session in recent)
        total += recent[session]$attempts;

    if (total >= ssh_threshold)
        {
        NOTICE([
            $note=SSH_Brute_Force,
            $conn=c,
            $msg=fmt(
                "T1110.001: %d inferred auth attempts across %d failed SSH sessions within %s",
                total, |recent|, ssh_window
            ),
            $identifier=fmt("%s:%s", src, dst),
            $suppress_for=ssh_window
        ]);
        }
    }
```

Technical justification:

- `ssh_auth_result` is documented as a final-result event, raised once per connection [3]. We use its failure status rather than labelling every SSH handshake as password guessing.
- Connection UID identifies a failure observation and prevents duplicate counting. Each session is weighted by the observed attempt count.
- The rolling time window expires earlier observations. The one-hour table expiry cleans up idle source-destination state; it is not the detection interval.
- Alert messages include both weighted attempts and failed-session cardinality, so analysts can understand why the rule fired.
- Event time is when Zeek determines the final result, not when the first or each individual authentication attempt occurred. Consequently, an alert can arrive after a long connection closes, and the window does not measure individual password-guess timestamps precisely.
- No tool-specific user agent, SSH client banner or attacker address is needed. A benign client can become suspicious if its behavior changes.

## 5. Validation methodology and commands

### 5.1 Initial detector replay

The rule was replayed separately against `ssh-hydra.pcap`, `ssh-control.pcap`, and the approximately 10-minute `benign.pcap` containing 20 successful SSH logins. The actual results were one Hydra notice and zero notices on both controls.

```bash
for capture in ssh-hydra ssh-control benign; do
    mkdir -p "logs/detect-$capture"
    docker run --rm --network none \
      -v "$PWD/captures:/pcaps:ro" \
      -v "$PWD/rules:/rules:ro" \
      -v "$PWD/logs/detect-$capture:/out" \
      -w /out --entrypoint zeek zeek/zeek:latest \
      -C -r "/pcaps/$capture.pcap" \
      /rules/ssh-detection.zeek LogAscii::use_json=T
done
```

`-C` was used for the known virtual network checksum-offload issue observed during initial visibility testing. In a different environment, investigate capture integrity rather than blindly disabling checksum checks.

### 5.2 Fresh validation (four separately captured scenarios, one trial each)

```bash
ssh_lab_sequence() {
    name="$1"; source="$2"; failures="$3"; successes="$4"; delay="$5"
    run_scan_test "$name" docker compose exec -T "$source" bash -c '
        login() {
            sshpass -p "$1" ssh \
                -o StrictHostKeyChecking=no \
                -o PreferredAuthentications=password \
                -o PubkeyAuthentication=no \
                -o NumberOfPasswordPrompts=1 \
                labuser@victim "echo Login successful"
            echo "Exit code: $?"
        }
        for i in $(seq 1 "$1"); do
            date -u
            login WrongPassword
            if [ "$2" -eq 0 ] && [ "$i" -lt "$1" ]; then
                sleep "$3"
            fi
        done
        for i in $(seq 1 "$2"); do
            date -u
            login LabUser123
        done
    ' sh "$failures" "$successes" "$delay"
}

start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
    ssh_lab_sequence ssh-boundary7 attacker 7 0 0
    ssh_lab_sequence ssh-boundary8-success client 8 1 0
    ssh_lab_sequence ssh-normal-burst client 0 12 0
    ssh_lab_sequence ssh-slow attacker 8 0 5
} 2>&1 | tee evidence/ssh-validation-traffic.txt

docker compose logs --no-color --timestamps --since "$start" victim \
    > evidence/ssh-validation-server.txt
```

| Test | Source | Ground truth from individual SSH command outputs | Captured packets | Observed detector result |
|---|---|---|---:|---|
| `ssh-boundary7` | Attacker | Seven denials (exit 255) | 182 | No alert — deliberate below-threshold evasion |
| `ssh-boundary8-success` | Normal client | Eight denials, followed by one successful login (exit 0) | 249 | One alert at eight inferred attempts |
| `ssh-normal-burst` | Normal client | 12 successful logins (exit 0) | 480 | No alert |
| `ssh-slow` | Attacker | Eight denials with 5-second added pauses | 208 | One alert at eight inferred attempts |

All four captures reported zero kernel drops. The shell loop's overall exit status was zero because it explicitly printed the outcome after each login; the individual login exit statuses establish success or failure. Server logs were saved for these four tests. The initial Hydra and benign-retry visibility experiments are the cases where per-source-port server counts were explicitly reviewed and compared in this report.

The slow sequence began its first login at 06:01:34 UTC and its eighth at 06:02:34 UTC. The actual detector alerted within the configured two-minute observation window. A separate shorter-window policy was **not actually replayed** for SSH, unlike the completed port scan comparison. We therefore cannot assert that two minutes was experimentally optimal, only that this slower sequence was detected.

## 6. Comparative experiment

From the observed `ssh.log` records, we retrospectively compared total connections, failed sessions and summed inferred attempts on failed sessions. The only custom rule actually executed was the eight-attempt/two-minute rule. Alternative feature counts and thresholds below are retrospective criteria, not independent deployed Zeek rules.

```python
failed = [r for r in rows if r.get('auth_success') is False]
attempts = sum(r.get('auth_attempts', 0) for r in failed)
total_sessions = len(rows)
successes = sum(r.get('auth_success') is True for r in rows)
unknown = sum('auth_success' not in r for r in rows)
```

Evidence: `evidence/ssh-feature-comparison.txt`.

| Capture | Total sessions | Failed sessions | Inferred attempts in failed sessions | Successful sessions | Unknown | Actual alert |
|---|---:|---:|---:|---:|---:|---|
| ssh-hydra | 5 | 4 | 12 | 0 | 1 | Yes |
| ssh-control | 5 | 2 | 2 | 3 | 0 | No |
| benign | 20 | 0 | 0 | 20 | 0 | No |
| ssh-boundary7 | 7 | 7 | 7 | 0 | 0 | No |
| ssh-boundary8-success | 9 | 8 | 8 | 1 | 0 | Yes |
| ssh-normal-burst | 12 | 0 | 0 | 12 | 0 | No |
| ssh-slow | 8 | 8 | 8 | 0 | 0 | Yes |

The retrospective script computes capture-wide sums (not exact rolling-window maxima). For the attack sequences, the relevant failures were generated within two minutes and the executed detector confirmed threshold 8. The ten-minute benign capture has no failed sessions, so it cannot reach an inferred-failure threshold, but its 20 successes do **not** establish that 20 sessions occurred within one two-minute window. The 12 rapid successful-login control is the meaningful demonstration that total-session counting could trigger a false positive at threshold eight.

### 6.1 Feature choice

| Criterion (threshold 8) | Hydra | 8 separate failed logins | 12 rapid successful logins |
|---|---|---|---|
| Total sessions | Miss | Detected | False alert |
| Failed sessions | Miss | Detected | Correct |
| Weighted attempts in failed sessions (executed rule) | Detected | Detected | Correct |

H1 is rejected because activity volume does not establish failure. H2 is useful but inadequate for Hydra in our observed case. H3 is the chosen feature because it captures multiple inferred authentication attempts inside the same failed connection while filtering successful and unknown sessions. H4 is supported by the retry control. H5 is supported for the eight-inferred-attempt boundary and the observed slower sequence, with a demonstrated below-threshold miss. H6 motivates a possible higher-confidence incident correlation feature; it is not required for the brute-force notice because Hydra never succeeded in our attack capture.

### 6.2 Threshold sensitivity

| Weighted inferred-attempt threshold | Detected among four attack episodes | False alerts on three controls | Evaluation method |
|---:|---:|---:|---|
| 5 | 4/4 | 0/3 | Retrospective |
| 8 | 3/4 | 0/3 | Actual Zeek rule |
| 12 | 1/4 | 0/3 | Retrospective |

Why retain eight when five detected more attacks on this dataset? The data does **not** prove eight is better than five. We retained the research-inspired candidate, which passed fresh threshold validation and avoided the observed ordinary retry activity. The five-attempt alternative is a promising more sensitive candidate but has not been executed or independently validated against realistic legitimate authentication failures, misconfigured jobs or other environments. Lowering it purely to catch the deliberately generated seven-attempt attack would overstate what this small test can justify. Further threshold calibration with more varied negative examples is a planned improvement, not a completed experiment.

## 7. Results and evidence

The unit of evaluation is a complete independently generated password-guessing episode or benign control capture, not individual password attempts, packets or replays. The initial one-failure visibility test predates this evaluation and is not counted as a brute-force positive.

| Phase | Attack episodes | Detected | Control episodes | False alerts |
|---|---:|---:|---:|---:|
| Initial Hydra and benign controls | 1 | 1 | 2 | 0 |
| Fresh validation | 3 | 2 | 1 | 0 |
| **Total** | **4** | **3** | **3** | **0** |

| Metric | Result |
|---|---:|
| True positives | 3 |
| False negatives | 1 (seven-attempt episode) |
| True negatives | 3 |
| False positives | 0 |
| Observed recall | 3/4 = 75% |
| Fresh-validation recall | 2/3 = 66.7% |
| Observed control false-positive rate | 0/3 = 0% |

The accepted eight-attempt condition was met in three attack episodes and detected in all three. The 75% overall result includes a deliberately generated evasion and the development attack. Do not present it as generic production accuracy or a statistically representative test. Each full scenario was executed once.

Actual alert messages:

```text
T1110.001: 12 inferred auth attempts across 4 failed SSH sessions within 2.0 mins
T1110.001: 8 inferred auth attempts across 8 failed SSH sessions within 2.0 mins
```

The Hydra alert originated from `172.30.77.20`; the eight-failure-then-success alert originated from `172.30.77.30`. This demonstrates that the rule does not depend on a predefined malicious IP.

Evidence files to retain in the repository:

- `captures/ssh-hydra.pcap`, `captures/ssh-control.pcap`, `captures/benign.pcap`.
- `captures/ssh-boundary7.pcap`, `captures/ssh-boundary8-success.pcap`, `captures/ssh-normal-burst.pcap`, `captures/ssh-slow.pcap`.
- `evidence/ssh-hydra-traffic.txt`, `evidence/ssh-control-traffic.txt`, `evidence/ssh-server-ground-truth.txt`.
- `evidence/ssh-validation-traffic.txt`, `evidence/ssh-validation-server.txt`, `evidence/ssh-feature-comparison.txt`.
- `logs/ssh-hydra/ssh.log`, `logs/ssh-control/ssh.log` (visibility), and `logs/detect-ssh-*/` (custom detector replay); `logs/detect-benign/`.
- `rules/ssh-detection.zeek`.

## 8. Limitations and holdbacks

| Limitation | Reason and impact | Future improvement (not implemented) |
|---|---|---|
| Below-threshold guessing (demonstrated) | Seven inferred attempts did not trigger. | Combine multiple signals or longer windows, calibrate lower thresholds on richer legitimate failures. |
| Inferred counts are imperfect (demonstrated) | Zeek estimated 12 attempts for 14 server failures. Encrypted packet patterns cannot directly reveal credential outcome or count. | Join endpoint sshd/PAM logs with network metadata; account for uncertainty instead of treating inference as ground truth. |
| Unknown outcomes | Missing auth result is deliberately ignored to avoid false claims. An incomplete or ambiguous attack might be missed. | Track unknown outcomes as telemetry-quality context; confirm with endpoint logs. |
| Compression, encryption and packet loss | SSH packet-size inference may become unreliable when compression is negotiated or observation is incomplete. All tested sessions used no compression. | Endpoint-based authentication events, capture quality checks, additional protocol variants. |
| Eventually successful connection with several prior failures | Because the rule ignores a successful final result, earlier wrong guesses in that same connection may be invisible to the score. | Use endpoint logs for per-attempt timing and success/failure; avoid assuming multiple authentication steps are wrong passwords. |
| Final-result timing | Attempts are credited together at final-session-result time; long sessions can delay alerts or affect window semantics. | Compare incremental evidence with event-level endpoint time; design detection for partial results with calibrated confidence. |
| Low-and-slow or distributed guessing | Source/destination grouping and two-minute window may miss attacks spread over sources, targets or longer intervals. | Multi-window/account-level detection, password-spraying analytics with trusted endpoint identity. |
| Legitimate repeated failures | Stale automation credentials or misconfigured services can exceed the threshold without malicious intent. Few benign failures were tested. | Baseline service accounts, distinguish users/roles with endpoint telemetry, test outage/misconfiguration traffic. |
| Session-level vs account-level grouping | SSH username is not directly visible in encrypted network records; attempts against different users from the same pair can be aggregated. | Enrich using server logs and account identity; maintain separate per-account and per-source counters. |
| Repeated-alert suppression | More than one attack from the same source/destination during 120 seconds may be grouped into one notice. | Incident-aware suppression and counters for continuing activity. |
| Limited experiment size | Only four attack episodes and three controls, one trial per scenario, no broad environment or performance benchmark. | Independent repeated tests, richer benign workloads, diverse SSH clients/authentication methods. |
| Post-access correlation not implemented | Eight failures followed by one success were observed, but the rule emits only the brute-force alert; it does not assert compromise. | In a later correlation layer, verify successful authentication with server evidence and analyze subsequent behavior. |

## 9. ATT&CK mapping and conclusion

Primary mapping: **T1110.001 — Password Guessing**, under Credential Access. This detector identifies evidence of repeated unsuccessful authentication, not password cracking, credential stuffing or verified compromise. SSH itself is relevant to T1021.004 when used as a remote service, but a password guessing notice alone does not establish lateral movement.

Our main contribution is an evidence-driven refinement of a simple failed-connection rule: independent server logs proved that several password attempts could occur inside one SSH connection and that Zeek's inferred counts were not exact. We selected a weighted failed-session detector that recognized the real Hydra attack, preserved the observed outcome uncertainty and rejected the legitimate high-volume login control. The result is interpretable and feasible in the hackathon scope. The next practical enhancement is endpoint-aware incident correlation, not a claim that encryption has been overcome or that every failed password is known to the network sensor.

## References

1. MITRE ATT&CK, [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/).
2. MITRE ATT&CK, [DET0551 — Password Guessing via Multi-Source Authentication Failure Correlation](https://attack.mitre.org/detectionstrategies/DET0551/).
3. Zeek 9.0.1, [SSH protocol script, `ssh_auth_result`, `ssh_auth_failed` and record fields](https://docs.zeek.org/en/lts/scripts/base/protocols/ssh/main.zeek.html).
4. Zeek, [SSH log reference](https://docs.zeek.org/en/current/reference/logs/ssh.html) and [SSH analyzer events](https://docs.zeek.org/en/lts/scripts/base/bif/plugins/Zeek_SSH.events.bif.zeek.html).
5. Zeek, [Built-in SSH brute-force policy](https://docs.zeek.org/en/current/scripts/policy/protocols/ssh/detect-bruteforcing.zeek.html) (`SSH::password_guesses_limit`, `SSH::guessing_timeout`).
6. Wazuh, [Testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html), rule 5712 example: eight failed nonexistent-user login events in two minutes.

External sources explain the detection approach and limitations; measured results are from the listed local captures, SSH server outputs and Zeek notices.
