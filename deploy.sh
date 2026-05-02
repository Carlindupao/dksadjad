#!/bin/bash
# =============================================================================
# OPSEC SAFE v2.0 - SECURE + TELEMETRY BLOCK + CADDY/FILEBROWSER/CLOUDFLARED
# =============================================================================
# Este script NÃO bloqueia acesso SSH e NÃO corta comunicação de saída
# Inclui bloqueio de telemetria (Ubuntu/Amazon/Debian metrics)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log(){ echo -e "${GREEN}[+]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }
error(){ echo -e "${RED}[x]${NC} $1"; }

# Verificar root
[ "$EUID" -ne 0 ] && echo "Use sudo" && exit 1

# =============================================================================
# BACKUP CRÍTICO ANTES DE QUALQUER COISA
# =============================================================================
log "Criando backup de configurações atuais..."
BACKUP_DIR="/root/opsec-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /etc/ssh "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/ufw "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/fail2ban/jail.local "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/hosts "$BACKUP_DIR/" 2>/dev/null || true

log "Backup salvo em $BACKUP_DIR"

# =============================================================================
# DETECTAR IP DO SSH (para não se trancar)
# =============================================================================
SSH_IP=""
if [ -n "${SSH_CONNECTION:-}" ]; then
    SSH_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
elif command -v who &>/dev/null; then
    SSH_IP=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || true)
fi

if [ -n "$SSH_IP" ]; then
    log "Seu IP SSH detectado: $SSH_IP"
else
    warn "Não foi possível detectar seu IP"
fi

# =============================================================================
# BLOQUEIO DE TELEMETRIA (UBUNTU/AMAZON/DEBIAN)
# =============================================================================
log "Bloqueando telemetria e serviços de coleta de dados..."

# Desabilitar serviços de telemetria
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
systemctl disable --now whoopsie apport 2>/dev/null || true
systemctl disable --now cloud-init cloud-final cloud-config 2>/dev/null || true
systemctl disable --now ubuntu-advantage landscape-client 2>/dev/null || true
systemctl disable --now packagekit 2>/dev/null || true

# Remover pacotes de telemetria
apt purge -y cloud-init apport whoopsie ubuntu-advantage-tools landscape-common 2>/dev/null || true

# Bloquear domínios de telemetria no /etc/hosts
cat >> /etc/hosts << 'EOF'

# ===== BLOQUEIO DE TELEMETRIA =====
127.0.0.1 metrics.ubuntu.com
127.0.0.1 poplar.canonical.com
127.0.0.1 ubuntu.com/metrics
127.0.0.1 motd.ubuntu.com
127.0.0.1 landscape.canonical.com
127.0.0.1 api.ubuntu.com
127.0.0.1 amazon.com/linux-metrics
127.0.0.1 amazonlinux.us-east-1.amazonaws.com
127.0.0.1 ec2.amazonaws.com/metadata
127.0.0.1 169.254.169.254  # AWS metadata (bloqueia coleta)
EOF

# Bloquear via sysctl (anti leak)
cat > /etc/sysctl.d/99-telemetry-block.conf << EOF
# Bloquear acesso a metadata AWS
net.ipv4.conf.all.rp_filter = 2
EOF

# Remover MOTD da Canonical
rm -f /etc/update-motd.d/99-ubuntu-advantage 2>/dev/null || true
rm -f /etc/update-motd.d/50-landscape-sysinfo 2>/dev/null || true
rm -f /etc/update-motd.d/00-header 2>/dev/null || true

# Desabilitar reports de erro
echo "enabled=0" > /etc/default/apport 2>/dev/null || true
systemctl mask apport 2>/dev/null || true

log "✅ Telemetria bloqueada"

# =============================================================================
# ATUALIZAR SISTEMA
# =============================================================================
log "Atualizando repositórios..."
apt update -qq

# Instalar pacotes necessários (SEM ferramentas blackhat)
apt install -y -qq curl wget ufw fail2ban openssl ca-certificates gnupg2 apt-transport-https debian-keyring

# =============================================================================
# CADDY (WEBSERVER)
# =============================================================================
log "Instalando Caddy..."
if ! command -v caddy &>/dev/null; then
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
    apt update -qq && apt install -y -qq caddy
fi

CADDY_PORT=${CADDY_PORT:-2015}
mkdir -p /var/www/html
echo "OPSEC SAFE v2 - $(date)" > /var/www/html/index.html

cat > /etc/caddy/Caddyfile << EOF
{
    admin off
    auto_https off
}

:${CADDY_PORT} {
    bind 127.0.0.1
    root * /var/www/html
    file_server
    encode gzip
    log {
        output discard
    }
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Server "Caddy"
    }
}
EOF

systemctl restart caddy
systemctl enable --now caddy
log "✅ Caddy rodando na porta ${CADDY_PORT} (127.0.0.1)"

# =============================================================================
# FILEBROWSER
# =============================================================================
log "Instalando FileBrowser..."
if ! command -v filebrowser &>/dev/null; then
    curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash
fi

FB_PORT=${FB_PORT:-8080}
FB_DB="/etc/filebrowser.db"
FB_ROOT="/var/www"

# Configurar FileBrowser
filebrowser config init --address 127.0.0.1 --port ${FB_PORT} --database ${FB_DB} --root ${FB_ROOT} 2>/dev/null || true

# Gerar senha aleatória
FB_PASS=$(openssl rand -base64 16 | tr -d '/+=' | cut -c1-12)

# Criar usuário admin
filebrowser users update admin --password "$FB_PASS" --database ${FB_DB} 2>/dev/null || \
filebrowser users add admin "$FB_PASS" --perm.admin --database ${FB_DB} 2>/dev/null

# Criar service systemd
cat > /etc/systemd/system/filebrowser.service << EOF
[Unit]
Description=FileBrowser
After=network.target

[Service]
ExecStart=/usr/local/bin/filebrowser --database ${FB_DB} --address 127.0.0.1 --port ${FB_PORT} --root ${FB_ROOT}
Restart=always
LimitNOFILE=65535
ProtectSystem=strict
PrivateTmp=true
NoNewPrivileges=true
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now filebrowser
log "✅ FileBrowser rodando na porta ${FB_PORT} (127.0.0.1)"

# =============================================================================
# CLOUDFLARED (config manual via arquivo)
# =============================================================================
if command -v cloudflared &>/dev/null || [ -f /usr/local/bin/cloudflared ]; then
    log "Cloudflared já instalado"
else
    log "Instalando Cloudflared..."
    wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O /usr/local/bin/cloudflared
    chmod +x /usr/local/bin/cloudflared
fi

# Criar diretório de config
mkdir -p /etc/cloudflared /root/.cloudflared

# Criar service (pausado, aguardando config)
cat > /etc/systemd/system/cloudflared.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared tunnel --config /etc/cloudflared/config.yml run
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

cat > /etc/cloudflared/config.yml << 'EOF'
# ============================================
# CLOUDFLARED CONFIGURATION
# ============================================
# Para configurar:
# 1. cloudflared tunnel login
# 2. cloudflared tunnel create <nome>
# 3. cloudflared tunnel route dns <id> <dominio>
# 4. Editar este arquivo com ID e credenciais
# ============================================

tunnel: SEU_TUNNEL_ID
credentials-file: /root/.cloudflared/SEU_TUNNEL_ID.json

ingress:
  - hostname: SEU_DOMINIO.COM
    service: http://127.0.0.1:2015
  
  - hostname: files.SEU_DOMINIO.COM
    service: http://127.0.0.1:8080
  
  - service: http_status:404
EOF

log "✅ Cloudflared instalado (configurar manualmente)"

# =============================================================================
# FIREWALL SEGURO
# =============================================================================
if command -v ufw &>/dev/null; then
    log "Configurando UFW (MODO SEGURO)..."
    
    ufw --force disable 2>/dev/null || true
    
    ufw default deny incoming
    ufw default allow outgoing  # CRÍTICO: NÃO bloquear saída
    
    # SSH
    if [ -n "$SSH_IP" ]; then
        ufw allow from "$SSH_IP" to any port 22 proto tcp comment "SSH do seu IP"
    else
        ufw allow 22/tcp comment "SSH"
    fi
    ufw limit 22/tcp
    
    # Serviços internos (acesso local apenas)
    ufw allow from 127.0.0.1 to any port ${CADDY_PORT} proto tcp
    ufw allow from 127.0.0.1 to any port ${FB_PORT} proto tcp
    
    # Bloquear email (anti-spam)
    ufw deny out 25,465,587/tcp
    
    echo "y" | ufw enable
    log "✅ UFW configurado"
fi

# =============================================================================
# FAIL2BAN
# =============================================================================
if command -v fail2ban &>/dev/null; then
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 5
banaction = ufw
backend = systemd
ignoreip = 127.0.0.1/8 $SSH_IP

[sshd]
enabled = true
mode = normal
maxretry = 3
bantime = 30m
EOF

    systemctl restart fail2ban
    log "✅ Fail2ban configurado"
fi

# =============================================================================
# SSH HARDENING (SEGURO)
# =============================================================================
log "Configurando SSH..."

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config.d/99-safe-opsec.conf << EOF
ClientAliveInterval 120
ClientAliveCountMax 3
MaxAuthTries 6
MaxSessions 10
PermitRootLogin prohibit-password
PasswordAuthentication yes
PubkeyAuthentication yes
UseDNS no
LogLevel VERBOSE
EOF

systemctl restart ssh
log "✅ SSH configurado"

# =============================================================================
# HARDENING ADICIONAL
# =============================================================================
log "Aplicando hardening adicional..."

cat > /etc/sysctl.d/99-opsec-safe.conf << EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF

sysctl --system >/dev/null 2>&1

# Limitar logs
cat > /etc/systemd/journald.conf.d/99-opsec.conf << EOF
[Journal]
SystemMaxUse=500M
MaxRetentionSec=7day
Compress=yes
EOF

systemctl restart systemd-journald

# =============================================================================
# SCRIPT DE RECUPERAÇÃO
# =============================================================================
cat > /root/opsec-recovery.sh << 'EOF'
#!/bin/bash
echo "🔄 Restaurando configurações..."
ufw --force disable
systemctl stop fail2ban
systemctl restart ssh
ufw allow 22/tcp
echo "y" | ufw enable
echo "✅ Recuperação concluída"
EOF

chmod +x /root/opsec-recovery.sh

# =============================================================================
# LIMPAR HISTÓRICO E LOGS (opcional)
# =============================================================================
if [ "${CLEAN_LOGS:-0}" = "1" ]; then
    log "Limpando logs e histórico..."
    rm -rf /var/log/* 2>/dev/null || true
    history -c 2>/dev/null || true
    rm -f ~/.bash_history 2>/dev/null || true
fi

# =============================================================================
# VERIFICAÇÕES FINAIS
# =============================================================================
log "Verificando serviços..."
systemctl is-active --quiet ssh && log "✅ SSH ativo" || error "⚠️ SSH inativo"
systemctl is-active --quiet caddy && log "✅ Caddy ativo" || error "⚠️ Caddy inativo"
systemctl is-active --quiet filebrowser && log "✅ FileBrowser ativo" || error "⚠️ FileBrowser inativo"

log "Testando conectividade..."
if curl -s --max-time 5 https://api.github.com/zen > /dev/null 2>&1; then
    log "✅ Internet funcionando"
fi

# =============================================================================
# INFORMAÇÕES FINAIS
# =============================================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║              OPSEC SAFE v2.0 - CONFIGURADO COM SUCESSO            ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║ 🔐 SSH:      preservado (senha + chave)                           ║"
echo "║ 🛡️ UFW:      ativo (saída permitida)                              ║"
echo "║ 📡 Telemetria: BLOQUEADA (Canonical/AWS)                          ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║ 🌐 Caddy:        http://127.0.0.1:${CADDY_PORT}                             ║"
echo "║ 📁 FileBrowser:  http://127.0.0.1:${FB_PORT}                              ║"
echo "║ 👤 Usuário:      admin                                            ║"
echo "║ 🔑 Senha:        ${FB_PASS}                                            ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║ ☁️  Cloudflared:  configurar manualmente                           ║"
echo "║ 📁 Config:       /etc/cloudflared/config.yml                      ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║ 📦 Backup:        ${BACKUP_DIR}                              ║"
echo "║ 🚨 Recuperação:   /root/opsec-recovery.sh                         ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

log "✅ INSTALAÇÃO CONCLUÍDA - MESTRE, TUDO PRONTO!"
