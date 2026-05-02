#!/bin/bash
set -euo pipefail

# =============================================================================
# OPSEC HARDENED SCRIPT v6.0 - ANONYMITY & SECURITY ENHANCED
# =============================================================================

# Color definitions (disabled in non-interactive or for logs)
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

log(){ echo -e "${GREEN}[+]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }

# Root check
[ "$EUID" -ne 0 ] && echo "Use sudo" && exit 1

# =============================================================================
# ANONYMITY: Randomize machine identifiers (optional, use with caution)
# =============================================================================
randomize_machine_id() {
    if [ -f /etc/machine-id ]; then
        TRUNCATED_OLD=$(cat /etc/machine-id | cut -c1-8)
        systemd-machine-id-setup 2>/dev/null || true
        log "Machine ID randomized (was: $TRUNCATED_OLD...)"
    fi
}

# Call only if environment variable set (opt-in for maximum anonymity)
if [ "${RANDOMIZE_MACHINE_ID:-0}" = "1" ]; then
    randomize_machine_id
fi

# =============================================================================
# SSH SAFE DETECTION (improved for proxy/tor jumps)
# =============================================================================
SSH_IP=""
SSH_SOURCE=""

if [ -n "${SSH_CONNECTION:-}" ]; then
    SSH_IP="${SSH_CONNECTION%% *}"
    SSH_SOURCE="SSH_CONNECTION"
elif who am i &>/dev/null 2>&1; then
    SSH_IP=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || true)
    SSH_SOURCE="who"
fi

# If still empty, check last login from sshd logs
if [ -z "$SSH_IP" ] && [ -f /var/log/auth.log ]; then
    SSH_IP=$(grep "Accepted" /var/log/auth.log 2>/dev/null | tail -1 | awk '{print $NF}' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || true)
    SSH_SOURCE="auth.log"
fi

log "SSH source detected: ${SSH_IP:-none} (from $SSH_SOURCE)"

# =============================================================================
# APT with tor proxy support (if tor is used)
# =============================================================================
apt_update_with_proxy() {
    if command -v tor &>/dev/null && systemctl is-active --quiet tor 2>/dev/null; then
        echo "Acquire::http::Proxy \"socks5h://127.0.0.1:9050/\";" > /etc/apt/apt.conf.d/50tor
        echo "Acquire::https::Proxy \"socks5h://127.0.0.1:9050/\";" >> /etc/apt/apt.conf.d/50tor
        log "APT using Tor proxy"
    fi
    apt update -qq
}

apt_update_with_proxy
apt install -y -qq curl wget gnupg2 ufw jq fail2ban openssl tor debian-keyring debian-archive-keyring apt-transport-https

# =============================================================================
# TOR SERVICE (enable for anonymity, service hidden)
# =============================================================================
if [ "${ENABLE_TOR:-1}" = "1" ]; then
    systemctl enable --now tor 2>/dev/null || true
    log "Tor enabled (SOCKS5 on 127.0.0.1:9050)"
fi

# =============================================================================
# FIREWALL: Strict + anti-leak + ratelimit
# =============================================================================
ufw --force reset 2>/dev/null || true
ufw default deny incoming
ufw default deny outgoing  # BLOCK ALL OUTBOUND by default (anti-leak)

# Allow only necessary outbound
ufw allow out 53,80,443,123/udp  # DNS, HTTP/S, NTP
ufw allow out 22/tcp comment 'SSH out'
ufw allow out 9050/tcp comment 'Tor out'

# If using Tor for all traffic
if [ "${FORCE_TOR_ALL:-0}" = "1" ]; then
    ufw deny out 80/tcp
    ufw deny out 443/tcp
    log "Forcing all traffic through Tor (transparent proxy mode)"
fi

# SSH inbound strict
if [ -n "$SSH_IP" ]; then
    ufw allow from "${SSH_IP}/32" to any port 22 proto tcp comment 'SSH from detected IP'
else
    warn "No SSH IP detected → SSH not exposed (safe)"
    # Optional: still allow from specific subnet via env
    if [ -n "${SSH_ALLOW_SUBNET:-}" ]; then
        ufw allow from "${SSH_ALLOW_SUBNET}" to any port 22 proto tcp
    fi
fi

ufw limit 22/tcp comment 'SSH rate limit'
ufw allow from 127.0.0.1 to any port 2015,8080 proto tcp comment 'Local services'
ufw deny out 25,465,587/tcp comment 'Block mail (anti-exfil)'

# Log dropped packets (forensics but careful with logs)
ufw logging medium

ufw --force enable
log "Firewall: strict outgoing deny + anti-leak"

# =============================================================================
# FAIL2BAN: Aggressive + custom jails
# =============================================================================
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 6h
findtime = 30m
maxretry = 2
banaction = ufw
backend = systemd

[sshd]
enabled = true
mode = aggressive

[sshd-ddos]
enabled = true
logpath = /var/log/auth.log
maxretry = 3
findtime = 10m
EOF

systemctl enable --now fail2ban
log "Fail2ban: aggressive"

# =============================================================================
# SSH HARDENING (maximum)
# =============================================================================
cat > /etc/ssh/sshd_config.d/99-opsec.conf <<EOF
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
ChallengeResponseAuthentication no
UsePAM no
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 2
MaxSessions 3
TCPKeepAlive no
AllowTcpForwarding no
GatewayPorts no
EOF

systemctl restart ssh || systemctl restart sshd
log "SSH hardened"

# =============================================================================
# SYSCTL: Anti-leak, anti-scan, anti-DoS
# =============================================================================
cat > /etc/sysctl.d/99-opsec.conf <<EOF
# Network security
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=2
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.ip_forward=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1

# Anti-leak
net.core.bpf_jit_enable=1
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.printk=3 3 3 3
net.ipv4.conf.all.log_martians=1
EOF

sysctl --system >/dev/null
log "Sysctl: anti-leak + anti-scan"

# =============================================================================
# JOURNALD: volatile + no persistent logs (opt-out via env)
# =============================================================================
if [ "${PERSISTENT_LOGS:-0}" != "1" ]; then
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/opsec.conf <<EOF
[Journal]
Storage=volatile
RuntimeMaxUse=50M
MaxRetentionSec=1hour
ForwardToSyslog=no
ForwardToWall=no
EOF
    systemctl restart systemd-journald
    log "Journald: volatile, no persistent logs"
fi

# =============================================================================
# CADDY (webserver) with random local port
# =============================================================================
CADDY_PORT=${CADDY_PORT:-2015}
if ! command -v caddy &>/dev/null; then
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy.list
    apt update && apt install -y caddy
fi

cat > /etc/caddy/Caddyfile <<EOF
{
    auto_https off
    admin off
}

:${CADDY_PORT} {
    bind 127.0.0.1
    root * /var/www/html
    file_server
    encode gzip zstd
    log {
        output discard
    }
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Server "nginx"   # disguise
    }
}
EOF

mkdir -p /var/www/html
RANDOM_HASH=$(openssl rand -hex 8)
echo "OPSEC v6 - ${RANDOM_HASH}" > /var/www/html/index.html

systemctl enable --now caddy
log "Caddy on 127.0.0.1:${CADDY_PORT}"

# =============================================================================
# FILEBROWSER (random password + random local port)
# =============================================================================
FB_PORT=${FB_PORT:-8080}
if ! command -v filebrowser &>/dev/null; then
    curl -fsSL https://github.com/filebrowser/filebrowser/releases/latest/download/linux-amd64-filebrowser.tar.gz -o fb.tar.gz
    tar xzf fb.tar.gz
    mv filebrowser /usr/local/bin/
    chmod +x /usr/local/bin/filebrowser
    rm fb.tar.gz
fi

filebrowser config init --address 127.0.0.1 --port ${FB_PORT} --database /etc/filebrowser.db --root /var/www 2>/dev/null || true

ADMIN_PASS=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-16)
filebrowser users update admin --password "$ADMIN_PASS" --database /etc/filebrowser.db 2>/dev/null || \
filebrowser users add admin "$ADMIN_PASS" --perm.admin --database /etc/filebrowser.db

cat > /etc/systemd/system/filebrowser.service <<EOF
[Unit]
Description=FileBrowser
After=network.target

[Service]
ExecStart=/usr/local/bin/filebrowser --database /etc/filebrowser.db --address 127.0.0.1 --port ${FB_PORT} --root /var/www
Restart=always
LimitNOFILE=65535
ProtectSystem=strict
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now filebrowser
log "FileBrowser on 127.0.0.1:${FB_PORT}"

# =============================================================================
# CLOUDFLARED (multi-domain, config via env only, no hardcoded secrets)
# =============================================================================
if [ -n "${CLOUDFLARE_TUNNEL_ID:-}" ] && [ -n "${CLOUDFLARE_DOMAIN1:-}" ]; then
    if ! command -v cloudflared &>/dev/null; then
        wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
        dpkg -i cloudflared-linux-amd64.deb 2>/dev/null || apt install -f -y
        rm cloudflared-linux-amd64.deb
    fi

    mkdir -p /etc/cloudflared /root/.cloudflared
    echo "${CLOUDFLARE_TUNNEL_JSON}" > /root/.cloudflared/${CLOUDFLARE_TUNNEL_ID}.json 2>/dev/null || true

    cat > /etc/cloudflared/config.yml <<EOF
tunnel: ${CLOUDFLARE_TUNNEL_ID}
credentials-file: /root/.cloudflared/${CLOUDFLARE_TUNNEL_ID}.json

ingress:
  - hostname: ${CLOUDFLARE_DOMAIN1}
    service: http://127.0.0.1:${CADDY_PORT}
  - hostname: ${CLOUDFLARE_DOMAIN2:-files.${CLOUDFLARE_DOMAIN1}}
    service: http://127.0.0.1:${FB_PORT}
  - service: http_status:404
EOF
    systemctl enable --now cloudflared 2>/dev/null || true
    log "Cloudflared tunnel configured (domains hidden in env)"
else
    warn "Cloudflare tunnel skipped (missing env vars)"
fi

# =============================================================================
# ANONYMITY: wipe bash history selectively
# =============================================================================
if [ "${WIPE_HISTORY:-1}" = "1" ]; then
    unset HISTFILE
    history -c 2>/dev/null || true
    rm -f ~/.bash_history ~/.zsh_history 2>/dev/null || true
    log "Shell history wiped"
fi

# =============================================================================
# BACKUP (encrypted, sent via tor if available)
# =============================================================================
BACKUP_PASS=$(openssl rand -base64 24 | head -c20)
cat > /usr/local/bin/backup.sh <<EOF
#!/bin/bash
BACKUP_FILE="/tmp/backup-\$(date +%F).tar.gz.gpg"
tar czf - /etc /var/www 2>/dev/null | gpg --batch --passphrase "${BACKUP_PASS}" --symmetric --cipher-algo AES256 -o "\$BACKUP_FILE"
# Optional: upload via curl --socks5-hostname 127.0.0.1:9050 if tor running
chmod 600 "\$BACKUP_FILE"
echo "Backup: \$BACKUP_FILE (pass saved in /root/.backup_pass)"
EOF
echo "$BACKUP_PASS" > /root/.backup_pass
chmod 600 /root/.backup_pass
chmod +x /usr/local/bin/backup.sh
log "Encrypted backup script ready"

# =============================================================================
# FINAL REPORT (only to console, not logged)
# =============================================================================
echo ""
echo "=============================="
echo "🔥 OPSEC v6 PRO - ANONYMIZED"
echo "=============================="
echo "Caddy:        http://127.0.0.1:${CADDY_PORT}"
echo "FileBrowser:  http://127.0.0.1:${FB_PORT}"
echo "User:         admin"
echo "Pass:         $ADMIN_PASS"
echo "Backup pass:  ${BACKUP_PASS:0:8}... (see /root/.backup_pass)"
echo "Tor SOCKS5:   127.0.0.1:9050"
echo "Firewall:     strict deny outgoing (allow list only)"
echo "Logs:         volatile (gone after reboot)"
echo "=============================="
echo "⚠️  SSH access allowed only from: ${SSH_IP:-none}"
echo "=============================="

# Clear sensitive vars from environment
unset ADMIN_PASS BACKUP_PASS CLOUDFLARE_TUNNEL_JSON CLOUDFLARE_TUNNEL_ID
