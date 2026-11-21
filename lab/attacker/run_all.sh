#!/bin/sh
# One attacker walks the kill chain against the lab victim: recon -> discovery -> credentials -> lateral movement.
# LAB ONLY. The target is fixed to the lab victim on purpose.
T=${TARGET:-10.0.0.10}
echo "[1/4] web wordlist fuzzing (T1595.003)";   /lab/attack_fuzz.sh "$T"; sleep 5
echo "[2/4] port scan (T1046)";                  /lab/attack_scan.sh "$T"; sleep 5
echo "[3/4] SSH password guessing (T1110.001)";  /lab/attack_ssh.sh  "$T"; sleep 5
echo "[4/4] SMB admin share access (T1021.002)"; /lab/attack_smb.sh  "$T"
echo "kill chain finished"
