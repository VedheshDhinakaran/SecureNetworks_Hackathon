# Tripwire

**Detection engineering as a measurable, continuously-verified pipeline.**
Tripwire detects four common network attacks with two independent sensors (Suricata and Zeek), merges alerts into incidents, explains the root cause with evidence, generates the fix, and proves the fix works.

> Detect &rarr; Correlate &rarr; Explain (root cause) &rarr; Fix &rarr; Verify

It answers the hackathon brief (PS3 "Tripwire": detections for port scanning, SSH password guessing, SMB admin-share access and web wordlist fuzzing) and adds the parts a real SOC needs: measured quality, evasion testing, correlation, root cause analysis and a live dashboard.

## Quick start (about 10 seconds, no Docker needed)

```bash
pip install -r requirements.txt
python -m tripwire test          # dataset -> sensors -> score -> incidents -> root cause -> reports; exit code 1 if the gate fails
start out/dashboard.html         # (Windows) or open it in any browser; fully offline
python -m tripwire serve         # live dashboard at http://127.0.0.1:8765 (replays the attacks as a live stream)
python -m pytest -q              # unit tests
```

With Docker running and `jasonish/suricata` and `zeek/zeek` pulled, `python -m tripwire test` automatically adds both real sensors and runs every capture through them. Check with `python -m tripwire engines`.

## Verification status

Verified by running it (Suricata 8.0.8, Zeek 9.0.1, Python 3.12, Windows + Docker Desktop):

**Synthetic dataset (39 labelled captures)**

- All captures through Suricata, Zeek and the native detector. All gates pass: 0 false alerts on benign and hard-negative traffic for every sensor, 100% recall on the core attacks, every threshold inside its measured safe band.
- The three sensors agree on every core attack, and the native detector matches Suricata L1 and Zeek L2 cell for cell on the speed grid.
- 12 unit tests pass. A loosened threshold makes the gate fail (see the judge sheet).

**Real Docker lab (victim with SSH, Samba and nginx; Kali attacker; Suricata and Zeek sidecars)**

- Real benign traffic (82 connections, including hard negatives): 0 alerts from all three sensors.
- Real kill chain (ffuf, nmap, hydra, smbclient): all four classes detected. hydra really found the weak password; the victim's `auth.log` confirms it, and the root-cause analysis reports the SSH impact as confirmed from that host log.
- Live mode: the platform container followed the sensor logs and produced incidents and root causes with live Zeek evidence.
- Live fix verification (`lab/verify.sh`): before the fix all four attacks succeed; after the generated fix pack SSH guessing and SMB `C$` are blocked, `/admin`, `/backup` and `/.git` return 403, and only port 80 is visible. Restored afterwards.
- SMB: the authorized admin host (10.0.3.5) opening `C$` and `ADMIN$` raised no alert; the same requests from a user host raised alerts with the server's verdict (granted, share missing). A request refused with access denied still alerts.

Not covered: encrypted SMB3, a compromised designated admin host, guessing spread over many source IPs (all documented as known gaps), and real Windows targets.

Things real testing taught us (all fixed):

- Suricata's default offline mode is multi-threaded, so time-window rules gave nondeterministic results. The runner uses `--runmode single`.
- Suricata appends to `eve.json`, so the runner wipes each capture's output folder first. Stale alerts had hidden the fix.
- The monitoring-poll hard negative false-alerted on an early layer-2 SSH threshold (10). The sweep showed a safe band of 12 to 16; the threshold is now 14.
- Our first benign generator opened 18 SSH connections from one host in 150 seconds and both sensors rightly flagged it. The generator is now realistic.
- Kali's nmap needs raw-socket capability inside a container (added to the compose file).
- Fix packs were written with Windows line endings, which broke the nftables file in the Linux victim. They are written with LF now.
- `PasswordAuthentication no` did not stop SSH guessing: with `UsePAM yes`, keyboard-interactive still accepts passwords. The fix and the playbook now also disable `KbdInteractiveAuthentication`. Found only by re-attacking the live lab.
- The first web fix hid `/backup` and `/.git` behind a rate limit instead of denying them. The playbook now denies them, and `verify.sh` fuzzes slowly so a rate limit cannot hide a path.
- SMB design ideas taken from a teammate's independent study, [SMB_Detection_Report.md](SMB_Detection_Report.md): allowlist the designated management hosts (a legitimate admin must not alert), record the server's outcome (granted, denied, share missing) instead of relying on successful mappings alone, and document the compromised-admin-host gap.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the diagram and the flow, step by step.

```
 DATA        Docker lab (real attacks)  +  scapy generator (39 labelled, reproducible PCAPs)
   |
 SENSORS     Suricata (L1, fast)   Zeek (L2, long window)   native Python plugin     <- all generated from ONE catalog.yml
   |
 PLATFORM    normalise -> enrich -> correlate -> root cause -> fix pack -> response plan -> verify
   |
 QUALITY     precision/recall, benign gate, threshold sweep, robustness grid, evasion matrix, self-validation canaries
   |
 OUTPUT      live dashboard, offline HTML, ATT&CK Navigator layer, report, detection-logic doc, Sigma rules
```

## What the brief asked for, and where it is

| Brief requirement | Where |
|---|---|
| Lab: attacker, victim (SSH, SMB, web), sensor | `docker-compose.yml`, `lab/` |
| Attack traffic for the 4 classes | `lab/attacker/*.sh` (nmap, hydra, smbclient, ffuf) and `tripwire/gen.py` |
| Benign baseline of at least 10 minutes | `benign` capture (11.6 min) and `lab/benign/benign_gen.sh` |
| One detection per class, Suricata or Zeek | `rules/tripwire.rules` (Suricata) and `zeek/tripwire.zeek` |
| Tuned: all detected, ~0 benign alerts | the acceptance gate in `python -m tripwire test` |
| ATT&CK IDs in each rule's metadata | every rule has `mitre_technique_id`; enforced by the lint check |
| Logic write-up with one evasion | `docs/DETECTION_LOGIC.md` (generated) and the evasion matrix |
| Table of true and false positives per class | `out/REPORT.md` and the dashboard Quality tab |
| Stretch: Sigma, enrichment, dashboard | `sigma/`, `tripwire/correlate.py`, `tripwire/dashboard.html` |

## Beyond the brief

- **Detection-as-code.** `detections/catalog.yml` is the single source of truth. Suricata rules, Zeek thresholds, the Navigator layer and the logic document are all generated from it.
- **Two layers, two sensors.** L1 (Suricata) is fast. L2 (Zeek) uses 5-minute windows to catch slow attacks that L1 misses. They are compared in the engine-agreement table.
- **Hard negatives.** Benign traffic that looks suspicious (mistyped passwords, a backup job, a monitoring poll, a developer hitting 404s). The monitoring poll genuinely tripped an early threshold; the sweep fixed it (see `tuning_note` in the catalog).
- **Threshold sweep.** For every class and layer, a ladder of thresholds is scored against all labelled traffic and the safe band is computed. The gate fails if a threshold leaves its band.
- **Robustness grid.** The same attack at decreasing speed shows exactly where detection stops.
- **Evasion matrix.** Slow, spoofed and distributed variants. One is a documented known gap.
- **Incident correlation.** Alerts become one incident per attacker with a kill-chain timeline, a risk score and engine consensus.
- **Root cause analysis.** YAML playbooks test hypotheses against the victim's real config files and the network evidence. Output: ranked causes, confidence, a three-tier fix and an ATT&CK mitigation each.
- **Fix pack and verification.** Generated config diffs are applied to a copy of the configs and every config test is re-run. `lab/verify.sh` re-runs the real attacks against the patched lab.
- **Response plan.** nftables block rules, dry-run by default, never targeting the management subnet or the victim.
- **Self-validation canaries.** Fresh randomised attacks are generated and checked against every sensor, so a silently broken rule turns the health pill red.
- **CI.** `.github/workflows/tripwire.yml` runs the whole regression suite on every push.

## Docker lab

```bash
docker compose up -d --build                       # victim, attacker, Suricata and Zeek sidecars, live platform
docker compose exec attacker /lab/run_all.sh       # real kill chain: fuzz -> scan -> SSH -> SMB
# http://localhost:8765                            # live dashboard follows data/live/*
docker compose --profile capture up capture        # record data/real_pcaps/lab_capture.pcap
python -m tripwire analyze data/real_pcaps         # detect, correlate and explain the real capture
lab/verify.sh check; lab/verify.sh apply INC-001; lab/verify.sh check    # live before/after
```

Attacks run only inside this lab. Never point these tools at another network.

## Judge variation commands

See [docs/JUDGE_SHEET.md](docs/JUDGE_SHEET.md): change a threshold, change the attack speed, add a new benign case, and re-run in seconds.

## Layout

```
detections/catalog.yml   single source of truth (thresholds, ATT&CK, D3FEND, mitigations)
rules/  zeek/            generated Suricata rules and Zeek script
sigma/                   log-based twins of the detections
playbooks/               root cause knowledge base (YAML)
tripwire/                platform: gen, native, engines, harness, correlate, rca, respond, validate, serve, report
lab/  docker-compose.yml real lab (victim with deliberately weak configs, attacker, benign users, sensors)
data/pcaps  manifest.json   labelled, reproducible dataset (ground truth)
out/                     generated: dashboard, REPORT.md, Navigator layer, fix packs, response plan
docs/                    ARCHITECTURE, DETECTION_LOGIC (generated), JUDGE_SHEET, DEMO_SCRIPT
tests/                   unit tests
```

## ATT&CK mapping

| Behavior | Technique | Tactic | D3FEND | Mitigations |
|---|---|---|---|---|
| Port scan | T1046 Network Service Discovery | Discovery | Connection Attempt Analysis, Network Traffic Analysis | M1031, M1037 |
| SSH password guessing | T1110.001 Password Guessing | Credential Access | Connection Attempt Analysis, Network Traffic Analysis | M1036, M1031, M1035 |
| SMB admin share | T1021.002 SMB/Windows Admin Shares | Lateral Movement | Network Traffic Analysis, Protocol Metadata Anomaly Detection | M1030, M1035, M1037 |
| Web wordlist fuzzing | T1595.003 Wordlist Scanning | Reconnaissance | Network Traffic Analysis, Protocol Metadata Anomaly Detection | M1037, M1050 |

IDs come from the hackathon brief. Confirm them against the current ATT&CK release and set `attack_version` in the catalog before you submit.

## Honest limitations

- Per-source counting cannot see guessing spread over many source IPs (`ev_distributed_ssh`). Roadmap: aggregate by destination.
- SSH is encrypted: the network cannot prove a login succeeded. The platform labels this a heuristic and confirms from the host `auth.log` when it is available.
- SMB3 encryption would hide share names from both sensors.
- The synthetic dataset proves repeatability and measures the detection envelope. The Docker lab produces authentic captures of the same attacks.
- Root cause analysis is deterministic hypothesis testing against known configs, not causal inference. That is deliberate: it is explainable and works offline.
- This is a prototype built on production-grade tools, not a production platform.
