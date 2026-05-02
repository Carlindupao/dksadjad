#!/bin/bash
set -euo pipefail

# Cores
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[✅]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[⚠️]${NC} $1"; }
log_error() { echo -e "${RED}[❌]${NC} $1"; }

#===============================================================================
# 0. ROOT + SSH SAFE DETECTION (FIXED)
#===============================================================================
if [ "$EUID" -ne 0 ]; then
  log_error "Use sudo."
  exit 1
fi

SSH_IP=""

if [ -n "${SSH_CONNECTION:-}" ]; then
  SSH_IP="${SSH_CONNECTION%% *}"
elif who am i &>/dev/null; then
  SSH_IP=$(who am i | awk '{print $5}' | tr -d '()')
fi

if [ -n "$SSH_IP" ]; then
  log_info "SSH detectado: $SSH_IP"
else
  log_warn "Não foi possível detectar IP SSH — fallback liberando porta 22 global"
fi

#===============================================================================
# 1. APT RETRY
#===============================================================================
retry_apt() {
  for i in {1..3}; do
    if apt update -qq && apt upgrade -y -qq; then return 0; fi
    sleep 3
  done
}
retry_apt

apt install -y -qq curl wget gnupg2 ufw jq fail2ban

#===============================================================================
# 2. FIREWALL (UFW HARDENED)
#===============================================================================
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing

# SSH safe
ufw allow from 127.0.0.1 to any port 22 proto tcp
if [ -n "$SSH_IP" ]; then
  ufw allow from "${SSH_IP}/32" to any port 22 proto tcp
else
  ufw allow 22/tcp
fi

# Rate limit SSH (anti brute)
ufw limit 22/tcp

# Local services
ufw allow from 127.0.0.1 to any port 2015 proto tcp
ufw allow from 127.0.0.1 to any port 8080 proto tcp

# Bloqueios comuns
ufw deny out to any port 25,465,587 proto tcp

ufw --force enable
log_info "Firewall ativo"

#===============================================================================
# 3. FAIL2BAN (ANTI BRUTE FORCE)
#===============================================================================
tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
EOF

systemctl enable --now fail2ban
log_info "Fail2Ban ativo"

#===============================================================================
# 4. SYSCTL HARDENING (ANTI SCAN / FLOOD)
#===============================================================================
tee /etc/sysctl.d/99-opsec.conf > /dev/null <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

net.ipv4.conf.all.accept_source_route = 0

net.ipv6.conf.all.disable_ipv6 = 1
EOF

sysctl --system >/dev/null
log_info "Sysctl hardening aplicado"

#===============================================================================
# 5. CADDY
#===============================================================================
if ! command -v caddy &> /dev/null; then
  apt install -y -qq debian-keyring debian-archive-keyring apt-transport-https
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy.gpg
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy.list
  apt update -qq && apt install -y -qq caddy
fi

tee /etc/caddy/Caddyfile > /dev/null <<EOF
{
    auto_https off
}

:2015 {
    bind 127.0.0.1

    handle {
        root * /var/www/html
        file_server
    }
}
EOF

mkdir -p /var/www/html
echo "OK" > /var/www/html/index.html

systemctl enable --now caddy

#===============================================================================
# 6. FILEBROWSER
#===============================================================================
if ! command -v filebrowser &> /dev/null; then
  curl -fsSL https://github.com/filebrowser/filebrowser/releases/latest/download/linux-amd64-filebrowser.tar.gz -o fb.tar.gz
  tar xzf fb.tar.gz
  mv filebrowser /usr/local/bin/
  chmod +x /usr/local/bin/filebrowser
  rm fb.tar.gz
fi

filebrowser config init --address 127.0.0.1 --port 8080 --database /etc/filebrowser.db --root /var/www || true

PASS=$(openssl rand -base64 12)
filebrowser users add admin "$PASS" --perm.admin --database /etc/filebrowser.db || true

tee /etc/systemd/system/filebrowser.service > /dev/null <<EOF
[Unit]
Description=FileBrowser
After=network.target

[Service]
ExecStart=/usr/local/bin/filebrowser --database /etc/filebrowser.db --address 127.0.0.1 --port 8080 --root /var/www
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now filebrowser

#===============================================================================
# 7. CLOUDLFARED
#===============================================================================
if ! command -v cloudflared &> /dev/null; then
  wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
  dpkg -i cloudflared-linux-amd64.deb || apt install -f -y
fi

mkdir -p /etc/cloudflared

#===============================================================================
# FINAL
#===============================================================================
echo ""
echo "============================="
echo "DEPLOY OPSEC v4 CONCLUÍDO"
echo "============================="
echo "FileBrowser: http://127.0.0.1:8080"
echo "User: admin"
echo "Senha: $PASS"
echo ""
echo "Caddy: http://127.0.0.1:2015"
echo ""
echo "Fail2Ban: ativo"
echo "Firewall: ativo"
echo "============================="
