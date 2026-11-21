# Judge sheet: re-run any check in seconds

All commands run from the repository root. `python -m tripwire test` is the single acceptance test: it exits 0 only if every gate passes.

| Check | Command | Expected |
|---|---|---|
| Full acceptance suite | `python -m tripwire test` | all gates PASS, exit code 0 |
| Which sensors are active | `python -m tripwire engines` | native ready; Suricata and Zeek ready when Docker runs |
| Rules carry ATT&CK IDs | `python -m tripwire build-rules` | both lint checks PASS |
| Every detection still works on fresh, randomised attacks | `python -m tripwire validate` | all classes green |
| Unit tests | `python -m pytest -q` | all pass |

## Variations a judge can apply

1. **Change a threshold and watch the gate react.** Edit `detections/catalog.yml`, for example set `ssh_bruteforce.l2.count` to `10`, then run `python -m tripwire test`. The monitoring-poll hard negative becomes a false positive, the benign gate fails, and the tuning gate shows the threshold is outside its measured safe band (12 to 16). Set it back to `14` to pass.
2. **Change the attack speed.** `python -m tripwire gen --seed 11` rebuilds the dataset with a different seed; or open the Robustness tab to see the same attack at six speeds and where each layer stops seeing it.
3. **Try an evasion.** The Evasion tab lists slow, spoofed and distributed variants. Slow ones are caught by L2 only; the distributed one is a documented known gap.
4. **Add a benign case.** Add a function in `tripwire/gen.py`, register it as a `hardneg` entry in `build_dataset`, and re-run. Any false positive fails the gate.
5. **Real lab variation** (Docker running): `TIMING=T1 docker compose exec -e TIMING=T1 attacker /lab/attack_scan.sh` for a slow scan; `docker compose exec -e WAIT=15 attacker /lab/attack_ssh.sh` for throttled guessing; `docker compose exec -e THREADS=2 -e DELAY=2 attacker /lab/attack_fuzz.sh` for slow fuzzing.
6. **Fix verification.** `lab/verify.sh check`, then `lab/verify.sh apply INC-001`, then `lab/verify.sh check` (before: attacks succeed; after: blocked). `lab/verify.sh restore` reverts.

## What each number means

- **Recall:** attacks detected, over the core attack captures.
- **False alerts:** alerts on benign and hard-negative captures. The gate requires zero.
- **Median time to detect:** seconds from the start of that attack stage to the first alert.
- **Safe band:** thresholds that sit above the noisiest benign behavior and below the weakest real attack.
