#!/bin/sh
# Judge-variation knob: TIMING (default T4). Use TIMING=T1 for a slow scan that Suricata L1 will miss.
T=${1:-10.0.0.10}
nmap -sS -p 1-1000 -"${TIMING:-T4}" "$T"
