#!/bin/sh
# Real-lab SSH validation suite: six SSH scenarios, each recorded as its own PCAP in data/real_pcaps/.
# Mirrors the independent study in SSH_Detection_Report.md. Run from the repo root with the lab up:
#   docker compose up -d victim attacker suricata zeek && sh lab/ssh_suite.sh
# Then: python -m tripwire real
# LAB ONLY: every login targets the lab victim with the lab's dummy account.
T=10.0.0.10
dc="docker compose"
mkdir -p data/real_pcaps

record() {   # record <name> <command...>: capture around one scenario
  name="$1"; shift
  $dc --profile capture run -d --no-deps --name "cap_$name" capture tcpdump -i eth0 -U -w "/pcaps/$name.pcap" >/dev/null 2>&1
  sleep 3
  "$@"
  sleep 3
  docker stop "cap_$name" >/dev/null 2>&1; docker rm "cap_$name" >/dev/null 2>&1
  echo "recorded $name"
}

# from the workstation container (has sshpass): <failures> <successes> <seconds between failures>
sequence() {
  $dc --profile benign run --rm --no-deps -T benign bash -c '
    login() {
      sshpass -p "$1" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 \
        deploy@'"$T"' "echo ok" >/dev/null 2>&1
    }
    for i in $(seq 1 "$1"); do login WrongPassword; [ "$3" -gt 0 ] && [ "$i" -lt "$1" ] && sleep "$3"; done
    for i in $(seq 1 "$2"); do login Summer2024!; done
  ' sh "$1" "$2" "$3" >/dev/null 2>&1
}

hydra_run() {
  $dc exec -T attacker sh -c '
    for i in $(seq 1 12); do printf "WrongLabPass%02d\n" "$i"; done > /tmp/pw.txt
    hydra -l deploy -P /tmp/pw.txt -t 2 ssh://'"$T"' >/dev/null 2>&1'
}

record ssh-hydra            hydra_run                 # real hydra, 12 wrong passwords, reuses connections
record ssh-control          sequence 2 3 0            # two typos then three successful logins
record ssh-boundary7        sequence 7 0 0            # seven failures: just below the threshold
record ssh-boundary8-success sequence 8 1 0           # eight failures, then a successful login
record ssh-normal-burst     sequence 0 12 0           # twelve successful logins in a row
record ssh-slow             sequence 8 0 5            # eight failures, five seconds apart
echo "suite finished: data/real_pcaps/ssh-*.pcap"
