#!/bin/bash
#===============================================================================
# [Lek Do BlacK] - Deploy Minimalista OPSEC v2.0
# Stack: Caddy + FileBrowser + Cloudflare Tunnel + Hardening
# Uso: curl -sL https://raw.githubusercontent.com/teu-user/repo/main/deploy.sh | sudo bash
# OU: wget -O deploy.sh URL && chmod +x deploy.sh && sudo ./deploy.sh
#===============================================================================

set -euo pipefail

# Cores pra output (opcional, mas ajuda no debug)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()    { echo -e "${GREEN}[✅]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[⚠️]${NC} $1"; }
log_error()   { echo -e "${RED}[❌]${NC} $1"; }

#===============================================================================
# 1. CHECK DE ROOT (FUNCIONA MESMO COM PIPE)
#===============================================================================
if [ "$EUID" -ne 0 ]; then
  log_error "ERRO: Rode com: curl ... | sudo bash  OU  sudo ./deploy.sh"
  exit 1
fi
log_info "Root confirmado. Iniciando deploy..."

#===============================================================================
# 2. RETRY NO APT (3 TENTATIVAS + DESBLOQUEIO)
#===============================================================================
retry_apt() {
  for i in {1..3}; do
    if apt update -qq && apt upgrade -y -qq; then
      return 0
    else
      log_warn "Tentativa $i de apt falhou, aguardando 5s..."
      sleep 5
      # Na última tentativa, força desbloqueio
      if [ $i -eq 3 ]; then
        log_warn "Forçando desbloqueio do apt..."
        killall -9 apt apt-get 2>/dev/null || true
        rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*
        dpkg --configure -a
        apt update -qq && apt upgrade -y -qq
      fi
    fi
  done
}
retry_apt

#===============================================================================
# 3. LIMPEZA OPSEC (REMOVE TELEMETRIA E AGENTES DESNECESSÁRIOS)
#===============================================================================
log_info "Removendo telemetria e agentes AWS..."
apt remove -y -qq snapd lxd cloud-init cloud-initramfs-* ubuntu-server 2>/dev/null || true
apt autoremove -y -qq
apt install -y -qq curl wget gnupg2 ufw jq

#===============================================================================
# 4. FIREWALL (UFW) - REGRAS CORRETAS COM proto tcp
#===============================================================================
log_info "Configurando firewall (UFW)..."
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing

# SSH: libera localhost + teu IP público (edita se necessário)
ufw allow from 127.0.0.1 to any port 22 proto tcp
#ufw allow from SEU_IP_PUBLICO/32 to any port 22 proto tcp  # DESCOMENTA E EDITA

# Serviços locais (Caddy + FileBrowser)
ufw allow from 127.0.0.1 to any port 2015 proto tcp  # Caddy admin
ufw allow from 127.0.0.1 to any port 8080 proto tcp  # FileBrowser

# Bloqueia portas sensíveis outbound (SMTP, DNS externo)
ufw deny out to any port 25,465,587 proto tcp  # SMTP
# DNS: usa 1.1.1.1 via tunnel se precisar, ou deixa liberado pra resolução local

ufw --force enable
log_info "Firewall configurado."

#===============================================================================
# 5. INSTALAR CADDY (REVERSE PROXY + SSL LOCAL)
#===============================================================================
log_info "Instalando Caddy..."
if ! command -v caddy &> /dev/null; then
  apt install -y -qq debian-keyring debian-archive-keyring apt-transport-https
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt update -qq && apt install -y -qq caddy
fi

# Configura Caddy minimalista
cat > /etc/caddy/Caddyfile << 'CADDY_EOF'
# Site principal (ajusta o domínio ou usa localhost)
:2015 {
    bind 127.0.0.1
    root * /var/www/html
    file_server
    encode gzip
    # Logs desativados pra OPSEC
    log {
        output discard
    }
}

# Fallback: 404 pra tudo que não casar
:2016 {
    bind 127.0.0.1
    respond "Not Found" 404
}
CADDY_EOF

# Cria diretório web padrão
mkdir -p /var/www/html
echo "<h1>🔒 Stack OPSEC ativa</h1>" > /var/www/html/index.html

# Testa config e inicia
if caddy adapt --config /etc/caddy/Caddyfile --validate >/dev/null 2>&1; then
  systemctl enable --now caddy
  log_info "Caddy instalado e rodando em 127.0.0.1:2015"
else
  log_error "Caddy config inválida. Verifique /etc/caddy/Caddyfile"
  exit 1
fi

#===============================================================================
# 6. INSTALAR FILEBROWSER (FILE MANAGER LEVE)
#===============================================================================
log_info "Instalando FileBrowser..."
if ! command -v filebrowser &> /dev/null; then
  curl -fsSL https://github.com/filebrowser/filebrowser/releases/latest/download/linux-amd64-filebrowser.tar.gz -o /tmp/fb.tar.gz
  tar xzf /tmp/fb.tar.gz -C /tmp
  mv /tmp/filebrowser /usr/local/bin/
  chmod +x /usr/local/bin/filebrowser
  rm -f /tmp/fb.tar.gz
fi

# Inicializa config se não existir
if [ ! -f /etc/filebrowser.db ]; then
  filebrowser config init \
    --address 127.0.0.1 \
    --port 8080 \
    --database /etc/filebrowser.db \
    --root /var/www
fi

# Cria/atualiza user admin (senha aleatória se não definida)
FB_PASS="${FB_ADMIN_PASS:-$(openssl rand -base64 12)}"
filebrowser users add admin "$FB_PASS" --perm.admin 2>/dev/null || \
filebrowser users update admin --password "$FB_PASS" 2>/dev/null || true

# Service systemd
cat > /etc/systemd/system/filebrowser.service << 'FB_EOF'
[Unit]
Description=FileBrowser OPSEC
After=network.target caddy.service

[Service]
User=root
ExecStart=/usr/local/bin/filebrowser --config /etc/filebrowser.db
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
FB_EOF

systemctl daemon-reload
systemctl enable --now filebrowser
log_info "FileBrowser instalado em 127.0.0.1:8080 (user: admin)"
log_warn "Senha admin: $FB_PASS  # SALVA ISSO AGORA!"

#===============================================================================
# 7. CLOUDFLARED (TUNNEL) - INSTALAÇÃO (CONFIGURAÇÃO MANUAL DEPOIS)
#===============================================================================
log_info "Instalando Cloudflare Tunnel..."
if ! command -v cloudflared &> /dev/null; then
  curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cf.deb
  dpkg -i /tmp/cf.deb 2>/dev/null || apt install -f -y -qq
  rm -f /tmp/cf.deb
fi

# Config padrão (edita depois com teu tunnel ID)
if [ ! -f /etc/cloudflared/config.yml ]; then
  cat > /etc/cloudflared/config.yml << 'CF_EOF'
# Edita: tunnel, credentials-file e ingress com teus dados
# tunnel: TEU_TUNNEL_ID
# credentials-file: /root/.cloudflared/TEU_TUNNEL_ID.json
#
# ingress:
#   - hostname: ajudeagora.sbs
#     service: http://127.0.0.1:2015
#   - hostname: files.ajudeagora.sbs
#     service: http://127.0.0.1:8080
#   - service: http_status:404
CF_EOF
  log_warn "Config do tunnel em /etc/cloudflared/config.yml — EDITA ANTES DE INICIAR"
fi

# Não inicia automático: espera tu configurar o tunnel primeiro
# systemctl enable --now cloudflared  # DESCOMENTA DEPOIS DE CONFIGURAR

#===============================================================================
# 8. HARDENING OPSEC (LOGS, OUTBOUND, CLEANUP)
#===============================================================================
log_info "Aplicando hardening OPSEC..."

# Desativa logs desnecessários do systemd
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/opsec.conf << 'JOURNAL_EOF'
[Journal]
Storage=volatile
MaxRetentionSec=1day
RateLimitIntervalSec=30s
RateLimitBurst=10000
JOURNAL_EOF
systemctl restart systemd-journald

# Rotação agressiva de logs
cat > /etc/logrotate.d/opsec-minimal << 'LOGROTATE_EOF'
/var/log/*.log /var/log/**/*.log {
  daily
  rotate 2
  compress
  delaycompress
  missingok
  notifempty
  create 0640 root root
  sharedscripts
  postrotate
    systemctl kill -s HUP systemd-journald.service 2>/dev/null || true
  endscript
}
LOGROTATE_EOF

# Cron de limpeza diária (3AM)
if ! crontab -l 2>/dev/null | grep -q "opsec-cleanup"; then
  (crontab -l 2>/dev/null; echo "0 3 * * * find /var/log -name '*.log' -mtime +2 -delete 2>/dev/null || true # opsec-cleanup") | crontab -
fi

# Desativa IPv6 (reduz fingerprint)
if ! grep -q "disable_ipv6" /etc/sysctl.conf; then
  echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
  echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
fi

log_info "Hardening aplicado."

#===============================================================================
# 9. BACKUP SCRIPT (RCLONE READY)
#===============================================================================
log_info "Criando script de backup mínimo..."
cat > /usr/local/bin/backup-opsec.sh << 'BACKUP_EOF'
#!/bin/bash
# Backup minimalista OPSEC - usa rclone se configurado
set -e

BACKUP_DIR="/tmp/backup-$(date +%F-%H%M)"
mkdir -p "$BACKUP_DIR"

# O que backupar
tar czf "$BACKUP_DIR/etc.tar.gz" /etc/caddy /etc/filebrowser.db /etc/cloudflared 2>/dev/null || true
tar czf "$BACKUP_DIR/www.tar.gz" /var/www 2>/dev/null || true

# Se rclone configurado, envia pra remote
if command -v rclone &> /dev/null && rclone listremotes | grep -q .; then
  rclone copy "$BACKUP_DIR" remote:backup-opsec/ --progress 2>/dev/null || log_warn "Rclone sync falhou"
fi

# Limpa local após 24h
find /tmp -name "backup-*" -mtime +1 -delete 2>/dev/null || true
BACKUP_EOF
chmod +x /usr/local/bin/backup-opsec.sh

# Agenda backup diário (4AM)
if ! crontab -l 2>/dev/null | grep -q "backup-opsec"; then
  (crontab -l 2>/dev/null; echo "0 4 * * * /usr/local/bin/backup-opsec.sh >> /var/log/backup-opsec.log 2>&1 # backup-opsec") | crontab -
fi
log_info "Backup script agendado (4AM diário)."

#===============================================================================
# 10. KERNEL REBOOT WARNING (NÃO BLOQUEANTE)
#===============================================================================
if [ -f /var/run/reboot-required ]; then
  log_warn "Kernel atualizado. Reboot recomendado (não obrigatório): sudo reboot"
fi

#===============================================================================
# 11. RESUMO FINAL + PRÓXIMOS PASSOS
#===============================================================================
echo ""
echo "==============================================================================="
echo "  [🔥] DEPLOY CONCLUÍDO - STACK MINIMALISTA OPSEC v2.0"
echo "==============================================================================="
echo "  📁 FileBrowser:  http://127.0.0.1:8080  | user: admin | pass: $FB_PASS"
echo "  🌐 Caddy:        http://127.0.0.1:2015  (serve /var/www/html)"
echo "  🚇 Cloudflared:  INSTALADO (config em /etc/cloudflared/config.yml)"
echo ""
echo "  [PRÓXIMOS PASSOS OBRIGATÓRIOS]"
echo "  1. Configura teu Cloudflare Tunnel:"
echo "     cloudflared tunnel login"
echo "     cloudflared tunnel create minimal-stack"
echo "     # Edita /etc/cloudflared/config.yml com teu tunnel ID e ingress"
echo "     cloudflared tunnel route dns minimal-stack ajudeagora.sbs"
echo "     cloudflared tunnel route dns minimal-stack files.ajudeagora.sbs"
echo "     systemctl enable --now cloudflared"
echo ""
echo "  2. No Cloudflare Dashboard:"
echo "     - SSL/TLS > Overview: Full (strict)"
echo "     - Sempre usa HTTPS: ✅"
echo "     - DNS records: ☁️ Proxied (nuvem laranja)"
echo ""
echo "  3. Testa localmente:"
echo "     curl -I http://127.0.0.1:2015"
echo "     curl -I http://127.0.0.1:8080"
echo ""
echo "  [OPSEC CHECKLIST]"
echo "  ✅ UFW: só localhost + teu IP liberado"
echo "  ✅ Logs: rotação + limpeza automática"
echo "  ✅ IPv6: desativado"
echo "  ✅ Backup: script agendado (configura rclone se quiser remoto)"
echo "  ✅ Zero telemetria: stack open-source, auditável"
echo "==============================================================================="
echo ""
log_info "Stack pronta. Agora é contigo, lek. 🔒"
