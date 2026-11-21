#!/bin/sh
# Benign baseline for DURATION seconds: browsing, ordinary SSH sessions, file-share use, plus
# "hard negatives" that look suspicious but are legitimate (mistyped password, monitoring poll).
# Usage: benign_gen.sh [seconds]
V=${VICTIM:-10.0.0.10}
END=$(( $(date +%s) + ${1:-720} ))
PW='Summer2024!'
n=0
while [ "$(date +%s)" -lt "$END" ]; do
  n=$((n+1))
  # browsing: a page and its assets
  for p in / /index.html; do curl -s -o /dev/null "http://$V$p"; done
  [ $((n % 5)) -eq 0 ] && curl -s -o /dev/null "http://$V/favicon.ico"      # one routine 404
  # ordinary admin SSH session
  [ $((n % 6)) -eq 0 ] && sshpass -p "$PW" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null deploy@"$V" 'uptime; sleep 5' >/dev/null 2>&1
  # file-share use of a named share (not an admin share)
  [ $((n % 6)) -eq 0 ] && smbclient "//$V/files" -U "deploy%$PW" -c 'ls' >/dev/null 2>&1
  # hard negative: user mistypes the password twice, then logs in
  if [ $((n % 9)) -eq 0 ]; then
    for i in 1 2; do sshpass -p wrongpass ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o NumberOfPasswordPrompts=1 deploy@"$V" true >/dev/null 2>&1; done
    sshpass -p "$PW" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null deploy@"$V" true >/dev/null 2>&1
  fi
  # hard negative: monitoring poll of the web and file-share ports (SSH is polled from the admin host, not here)
  [ $((n % 3)) -eq 0 ] && for port in 80 445; do nc -z -w1 "$V" $port; done
  sleep $((RANDOM % 8 + 5)) 2>/dev/null || sleep 8
done
echo "benign generator finished"
