FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server samba nginx nftables iproute2 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Deliberately weak account: its password is in the attacker's wordlist.
RUN useradd -m -s /bin/bash deploy && echo 'deploy:Summer2024!' | chpasswd \
    && printf 'Summer2024!\nSummer2024!\n' | smbpasswd -a -s deploy \
    && mkdir -p /run/sshd /srv/files /srv/c_drive /var/www/html/admin /var/www/html/backup /var/www/html/.git /var/log/hostlogs \
    && echo "quarterly numbers" > /srv/files/report.txt \
    && echo "C: drive contents" > /srv/c_drive/boot.ini \
    && echo "<h1>Welcome</h1>" > /var/www/html/index.html \
    && echo "admin console" > /var/www/html/admin/index.html \
    && echo "db dump" > /var/www/html/backup/db.sql.bak \
    && echo "ref: refs/heads/main" > /var/www/html/.git/HEAD \
    && rm -f /etc/nginx/sites-enabled/default
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22 80 445
ENTRYPOINT ["/entrypoint.sh"]
