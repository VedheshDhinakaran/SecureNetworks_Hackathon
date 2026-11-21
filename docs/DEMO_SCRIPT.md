# Demo script (5 to 7 minutes)

Before you start: run `python -m tripwire test` once so `out/` is fresh, and have `out/dashboard.html` open in a tab. If Docker works, start the lab; if not, everything below still runs.

| Time | Say | Show |
|---|---|---|
| 0:00 | "SOCs do not struggle to write a detection rule. They struggle to know it is good, to understand why the attack worked, and to fix it. Tripwire does all three." | Title and the five-step flow strip on the Overview tab |
| 0:30 | "Two independent sensors see the same traffic: Suricata is fast, Zeek watches longer windows. Everything is generated from one catalog, so nothing drifts." | `docs/ARCHITECTURE.md` diagram |
| 1:15 | "One command is the acceptance test." | Terminal: `python -m tripwire test`, then point at the gate: benign alerts 0, recall 100% |
| 2:15 | "Alerts become one incident per attacker, with a kill chain and a risk score." | Incidents tab: the critical incident, timeline, two-sensor confidence |
| 3:00 | "Now why was this possible?" | Root cause tab: impact, ranked causes with evidence, three-tier fix, ATT&CK mitigation |
| 3:45 | "We apply the fix to a copy of the real configs and re-run every test." | Verification line: causes cleared; fix pack diff in `out/fixpack/` |
| 4:15 | "Thresholds are measured, not guessed." | Quality tab: sweep chart; mention the monitoring-poll false positive that the sweep fixed |
| 4:45 | "Where does it stop seeing?" | Robustness grid and Evasion matrix; name the known gap (distributed guessing) |
| 5:30 | "Judge, change any threshold." | Edit `catalog.yml`, run the test, show the gate failing, revert |
| 6:15 | "It also runs live, and it checks its own detections continuously." | `python -m tripwire serve` live feed; health pill from the canaries |
| 6:45 | Close | "Detect, correlate, explain, fix, verify, with every number computed from labelled traffic." |

## Likely questions

- **Is the traffic real?** Two sources: the Docker lab produces authentic captures; the generator produces reproducible, labelled captures. Ground truth is exact for the generated set.
- **Why not machine learning?** Rules are explainable, auditable and map to ATT&CK. The threshold sweep brings the measurement rigor.
- **What does it miss?** Guessing distributed across many source IPs, and share names under SMB3 encryption. Both are in the evasion matrix and limitations.
- **Is auto-response safe?** Dry-run by default, allowlisted, and limited to the lab.
