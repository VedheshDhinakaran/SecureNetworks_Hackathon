#!/bin/sh
# Judge-variation knobs: THREADS (default 40) and DELAY seconds between requests (default 0).
T=${1:-10.0.0.10}
ffuf -u "http://$T/FUZZ" -w /lab/wordlist.txt -mc 200,301,403 -t "${THREADS:-40}" -p "${DELAY:-0}" -s
