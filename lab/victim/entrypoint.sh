#!/bin/sh
# Victim: install the (deliberately weak) configs from /conf and start SSH, Samba, nginx.
# Re-running this script after changing /conf is how the fix pack is applied for live verification.
set -e
install_conf() {
  cp /conf/sshd_config /etc/ssh/sshd_config
  cp /conf/smb.conf    /etc/samba/smb.conf
  cp /conf/default.conf /etc/nginx/conf.d/default.conf
  nft -f /conf/nftables.conf 2>/dev/null || echo "nft not applied (kernel or capability missing)"
}
install_conf
# sshd logs to a file we share with the host, so the platform can confirm real logins in auth.log
/usr/sbin/sshd -E /var/log/hostlogs/auth.log
smbd --foreground --no-process-group &
nginx
echo "victim ready: ssh:22 smb:445 http:80"
tail -f /dev/null
