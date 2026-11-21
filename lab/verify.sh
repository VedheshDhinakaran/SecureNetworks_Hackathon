#!/bin/sh
# Live fix verification against the Docker lab (run from the repo root, lab running).
#   lab/verify.sh check            run the four attacks, print whether each one still SUCCEEDS
#   lab/verify.sh apply INC-001    apply the generated fix pack to the victim and restart it
#   lab/verify.sh restore          put the original (weak) configs back
# Typical demo:  check  ->  apply INC-001  ->  check   (before: attacks succeed, after: they fail)
# LAB ONLY. Applying a fix pack changes the lab victim's configs; review out/fixpack/<id>/changes.diff first.
T=10.0.0.10
dc="docker compose"
case "$1" in
  check)
    echo "== SSH guessing"; out=$($dc exec -T attacker sh -c "hydra -l deploy -P /lab/passwords.txt -t 4 -f ssh://$T 2>&1" || true)
    echo "$out" | grep -q "1 valid password" && echo "   STILL SUCCEEDS: valid password found" || echo "   BLOCKED: no valid password found"
    echo "== SMB admin share"; if $dc exec -T attacker sh -c "smbclient '//$T/C\$' -U 'deploy%Summer2024!' -c ls" >/dev/null 2>&1; then echo "   STILL SUCCEEDS: C\$ listed"; else echo "   BLOCKED: C\$ not reachable"; fi
    echo "== Web fuzz"; n=$($dc exec -T attacker sh -c "ffuf -u http://$T/FUZZ -w /lab/wordlist.txt -mc 200,301 -s 2>/dev/null | wc -l" || echo 0)
    echo "   hidden paths discovered: $n"
    echo "== Port scan"; n=$($dc exec -T attacker sh -c "nmap -sS -p 1-1000 --open -oG - $T 2>/dev/null | grep -o '/open/' | wc -l" || echo 0)
    echo "   open ports visible to attacker: $n"
    ;;
  apply)
    pack="out/fixpack/${2:?usage: verify.sh apply INC-001}"
    [ -d lab/victim/conf.original ] || cp -r lab/victim/conf lab/victim/conf.original
    for f in "$pack"/*; do case "$f" in *changes.diff|*FIXES.md) ;; *) cp "$f" lab/victim/conf/ ;; esac; done
    $dc restart victim && sleep 6 && echo "fix pack applied; run: lab/verify.sh check"
    ;;
  restore)
    [ -d lab/victim/conf.original ] && cp lab/victim/conf.original/* lab/victim/conf/ && rm -rf lab/victim/conf.original
    $dc restart victim && echo "original configs restored"
    ;;
  *) echo "usage: $0 check | apply INC-ID | restore"; exit 2 ;;
esac
