#!/bin/sh
# Real-lab HTTP validation suite: eleven web scenarios, each recorded as its own PCAP in data/real_pcaps/.
# Mirrors the independent study in HTTP_Detection_Report.md. Run from the repo root with the lab up:
#   docker compose up -d victim attacker suricata zeek && sh lab/http_suite.sh
# Then: python -m tripwire real
# LAB ONLY: every request targets the lab victim.
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

# real ffuf from the attacker: <count> <prefix>; -mc all so every status is shown, browser-like user agent
ffuf_run() {
  $dc exec -T attacker sh -c '
    seq 1 '"$1"' | sed "s/^/'"$2"'-/" > /tmp/wl.txt
    ffuf -w /tmp/wl.txt -u http://'"$T"'/FUZZ -mc all -rate 30 -t 10 -H "User-Agent: Mozilla/5.0" -s >/dev/null 2>&1'
}

# curl loops from the workstation container (a different source address from the attacker)
client() {
  $dc --profile benign run --rm --no-deps -T benign bash -c "$1" >/dev/null 2>&1
}
repeated()  { client 'for i in $(seq 1 120); do curl -s -o /dev/null http://'"$T"'/missing-image.png; done'; }
query()     { client 'for i in $(seq 1 120); do curl -s -o /dev/null "http://'"$T"'/missing-image.png?id=$i"; done'; }
normal()    { client 'for i in $(seq 1 120); do curl -s -o /dev/null http://'"$T"'/; done'; }
broken()    { client 'for i in $(seq 1 60); do curl -s -o /dev/null http://'"$T"'/; curl -s -o /dev/null http://'"$T"'/; curl -s -o /dev/null "http://'"$T"'/missing-asset-$i.png"; done'; }
curl50()    { client 'for i in $(seq 1 50); do curl -s -o /dev/null "http://'"$T"'/fresh-path-$i"; done'; }
b49()       { client 'for i in $(seq 1 49); do curl -s -o /dev/null "http://'"$T"'/test-$i"; done'; }
b24()       { client 'for i in $(seq 1 50); do p=$(( (i - 1) % 24 + 1 )); curl -s -o /dev/null "http://'"$T"'/test-$p"; done'; }
b25()       { client 'for i in $(seq 1 50); do p=$(( (i - 1) % 25 + 1 )); curl -s -o /dev/null "http://'"$T"'/test-$p"; done'; }
padded() {   # the attacker pads a wordlist scan with successful requests
  $dc exec -T attacker sh -c 'for i in $(seq 1 60); do curl -s -o /dev/null http://'"$T"'/; curl -s -o /dev/null http://'"$T"'/; curl -s -o /dev/null "http://'"$T"'/probe-path-$i"; done' >/dev/null 2>&1
}

record http-ffuf150          ffuf_run 150 lab-path
record http-ffuf60           ffuf_run 60 small-path
record http-curl50           curl50
record http-repeated         repeated
record http-query            query
record http-normal           normal
record http-broken-app       broken
record http-padded-scan      padded
record http-boundary49       b49
record http-boundary24paths  b24
record http-boundary25paths  b25
echo "suite finished: data/real_pcaps/http-*.pcap"
