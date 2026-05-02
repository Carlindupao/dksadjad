#!/bin/bash
#===============================================================================
# [Lek Do BlacK] - Deploy Minimalista OPSEC v3.0 (SSH-SAFE + PRODUCTION READY)
# Stack: Caddy + FileBrowser + Cloudflare Tunnel + Hardening
# Uso: curl -sL https://raw.githubusercontent.com/teu-user/repo/main/deploy.sh | sudo bash
# OU: wget -O deploy.sh URL && chmod +x deploy.sh && sudo ./deploy.sh
#===============================================================================

set -euo pipefail

# Cores
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[✅]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[⚠️]${NC} $1"; }
log_error() { echo -e "${RED}[❌]${NC} $1"; }

#===============================================================================
# 0. CHECK DE ROOT + SSH SAFETY
#===============================================================================
if [ "$EUID" -ne 0 ]; then
  log_error "ERRO: Rode com: curl ... | sudo bash  OU  sudo ./deploy.sh"
  exit 1
fi

# Salva o IP da sessão SSH atual pra não se trancar
SSH_IP="${SSH_CONNECTION%% *}"
if [ -n "$SSH_IP" ]; then
  log_info "SSH detectado: $SSH_IP — regra de firewall será aplicada"
fi

log_info "Root confirmado. Iniciando deploy OPSEC v3.0..."

#===============================================================================
# 1. RETRY NO APT (3 TENTATIVAS + DESBLOQUEIO)
#===============================================================================
retry_apt() {
  for i in {1..3}; do
    if apt update -qq 2>&1 && apt upgrade -y -qq 2>&1; then return 0; else
      log_warn "Tentativa $i de apt falhou, aguardando 5s..."; sleep 5
      if [ $i -eq 3 ]; then
        log_warn "Forçando desbloqueio do apt..."
        killall -9 apt apt-get 2>/dev/null || true
        rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock*
        dpkg --configure -a 2>/dev/null || true
        apt update -qq && apt upgrade -y -qq
      fi
    fi
  done
}
retry_apt

#===============================================================================
# 2. LIMPEZA OPSEC (REMOVE TELEMETRIA)
#===============================================================================
log_info "Removendo telemetria e agentes AWS..."
apt remove -y -qq snapd lxd cloud-init cloud-initramfs-* ubuntu-server 2>/dev/null || true
apt autoremove -y -qq
apt install -y -qq curl wget gnupg2 ufw jq

#===============================================================================
# 3. FIREWALL (UFW) - SSH-SAFE + proto tcp OBRIGATÓRIO
#===============================================================================
log_info "Configurando firewall (UFW) — SSH-SAFE..."
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing

# ✅ SSH: libera localhost + IP da sessão atual (se detectado)
ufw allow from 127.0.0.1 to any port 22 proto tcp
if [ -n "$SSH_IP" ]; then
  ufw allow from "${SSH_IP}/32" to any port 22 proto tcp 2>/dev/null || true
fi

# ✅ Serviços locais (Caddy + FileBrowser) — SÓ localhost acessa
ufw allow from 127.0.0.1 to any port 2015 proto tcp  # Caddy
ufw allow from 127.0.0.1 to any port 8080 proto tcp  # FileBrowser

# ✅ Bloqueia outbound sensível (SMTP)
ufw deny out to any port 25,465,587 proto tcp

# ✅ Ativa UFW (sem perguntar)
ufw --force enable
log_info "Firewall configurado. SSH preservado."

#===============================================================================
# 4. INSTALAR CADDY (REVERSE PROXY + auto_https OFF)
#===============================================================================
log_info "Instalando Caddy..."
if ! command -v caddy &> /dev/null; then
  apt install -y -qq debian-keyring debian-archive-keyring apt-transport-https
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt update -qq && apt install -y -qq caddy
fi

# ✅ Caddyfile com auto_https OFF + bind explícito + routing por Host
sudo tee /etc/caddy/Caddyfile > /dev/null << 'CADDYEOF'
{
    auto_https off
}

:2015 {
    bind 127.0.0.1
    
    @files host files.*
    handle @files {
        reverse_proxy 127.0.0.1:8080
    }
    
    @main host *
    handle @main {
        root * /var/www/html
        file_server
        encode gzip
    }
    
    respond "Not Found" 404
    
    log { output discard }
}
CADDYEOF

# Cria conteúdo mínimo
mkdir -p /var/www/html
echo '<!DOCTYPE html><html><head><title>OPSEC</title></head><body><h1>🔒 Stack ativa</h1></body></html>' | tee /var/www/html/index.html > /dev/null
chmod 644 /var/www/html/index.html

# Valida + inicia
if caddy adapt --config /etc/caddy/Caddyfile --validate >/dev/null 2>&1; then
  systemctl enable --now caddy
  log_info "Caddy instalado e rodando em 127.0.0.1:2015"
else
  log_error "Caddy config inválida"; exit 1
fi

#===============================================================================
# 5. INSTALAR FILEBROWSER (FLAG --database CORRETA)
#===============================================================================
log_info "Instalando FileBrowser..."
if ! command -v filebrowser &> /dev/null; then
  curl -fsSL https://github.com/filebrowser/filebrowser/releases/latest/download/linux-amd64-filebrowser.tar.gz -o /tmp/fb.tar.gz
  tar xzf /tmp/fb.tar.gz -C /tmp
  mv /tmp/filebrowser /usr/local/bin/
  chmod +x /usr/local/bin/filebrowser
  rm -f /tmp/fb.tar.gz
fi

# Inicializa DB se não existir
if [ ! -f /etc/filebrowser.db ]; then
  filebrowser config init --address 127.0.0.1 --port 8080 --database /etc/filebrowser.db --root /var/www
fi

# Cria/atualiza user admin
FB_PASS="${FB_ADMIN_PASS:-$(openssl rand -base64 12)}"
filebrowser users add admin "$FB_PASS" --perm.admin --database /etc/filebrowser.db 2>/dev/null || \
filebrowser users update admin --password "$FB_PASS" --database /etc/filebrowser.db 2>/dev/null || true

# ✅ Service com flag --database CORRETA (não --config)
tee /etc/systemd/system/filebrowser.service > /dev/null << 'FBEOF'
[Unit]
Description=FileBrowser OPSEC
After=network.target caddy.service

[Service]
User=root
ExecStart=/usr/local/bin/filebrowser --database /etc/filebrowser.db --address 127.0.0.1 --port 8080 --root /var/www
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
FBEOF

systemctl daemon-reload
systemctl enable --now filebrowser
log_info "FileBrowser instalado em 127.0.0.1:8080 (user: admin)"
log_warn "Senha admin: $FB_PASS  # SALVA ISSO AGORA!"

#===============================================================================
# 6. CLOUDFLARED (TUNNEL) - mkdir -p ANTES DE ESCREVER
#===============================================================================
log_info "Instalando Cloudflare Tunnel..."
if ! command -v cloudflared &> /dev/null; then
  curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cf.deb
  dpkg -i /tmp/cf.deb 2>/dev/null || apt install -f -y -qq
  rm -f /tmp/cf.deb
fi

# ✅ CRIA A PASTA ANTES DE ESCREVER O ARQUIVO (BUG FIX v2.1+)
mkdir -p /etc/cloudflared
chmod 700 /etc/cloudflared

# Config padrão (edita depois com teu tunnel ID)
if [ ! -f /etc/cloudflared/config.yml ]; then
  tee /etc/cloudflared/config.yml > /dev/null << 'CFEOF'
# === EDITA ISSO DEPOIS COM TEUS DADOS ===
# tunnel: TEU_TUNNEL_ID_AQUI
# credentials-file: /root/.cloudflared/TEU_TUNNEL_ID_AQUI.json
# ingress:
#   - hostname: teudominio.com
#     service: http://127.0.0.1:2015
#   - hostname: files.teudominio.com
#     service: http://127.0.0.1:8080
#   - service: http_status:404
CFEOF
  chmod 600 /etc/cloudflared/config.yml
  log_warn "Config do tunnel em /etc/cloudflared/config.yml — EDITA ANTES DE INICIAR"
fi

log_info "Cloudflared instalado. Configure o tunnel manualmente:"
log_info "  1. cloudflared tunnel login"
log_info "  2. cloudflared tunnel create minimal-stack"
log_info "  3. Edita /etc/cloudflared/config.yml com teu tunnel ID"
log_info "  4. cloudflared tunnel route dns minimal-stack teudominio.com"
log_info "  5. systemctl enable --now cloudflared"

#===============================================================================
# 7. HARDENING OPSEC (LOGS, OUTBOUND, CLEANUP)
#===============================================================================
log_info "Aplicando hardening OPSEC..."

# Journald minimalista
mkdir -p /etc/systemd/journald.conf.d
tee /etc/systemd/journald.conf.d/opsec.conf > /dev/null << 'JEOF'
[Journal]
Storage=volatile
MaxRetentionSec=1day
RateLimitIntervalSec=30s
RateLimitBurst=10000
JEOF
systemctl restart systemd-journald 2>/dev/null || true

# Rotação agressiva de logs
tee /etc/logrotate.d/opsec-minimal > /dev/null << 'LEOF'
/var/log/*.log /var/log/**/*.log {
  daily; rotate 2; compress; delaycompress; missingok; notifempty; create 0640 root root; sharedscripts
  postrotate; systemctl kill -s HUP systemd-journald.service 2>/dev/null || true; endscript
}
LEOF

# Cron de limpeza diária
if ! crontab -l 2>/dev/null | grep -q "opsec-cleanup"; then
  (crontab -l 2>/dev/null; echo "0 3 * * * find /var/log -name '*.log' -mtime +2 -delete 2>/dev/null || true # opsec-cleanup") | crontab -
fi

# Desativa IPv6
if ! grep -q "disable_ipv6" /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
  echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
fi

#===============================================================================
# 8. BACKUP SCRIPT (RCLONE READY)
#===============================================================================
log_info "Criando script de backup mínimo..."
tee /usr/local/bin/backup-opsec.sh > /dev/null << 'BEOF'
#!/bin/bash; set -e
BACKUP_DIR="/tmp/backup-$(date +%F-%H%M)"; mkdir -p "$BACKUP_DIR"
tar czf "$BACKUP_DIR/etc.tar.gz" /etc/caddy /etc/filebrowser.db /etc/cloudflared 2>/dev/null || true
tar czf "$BACKUP_DIR/www.tar.gz" /var/www 2>/dev/null || true
if command -v rclone &> /dev/null && rclone listremotes 2>/dev/null | grep -q .; then
  rclone copy "$BACKUP_DIR" remote:backup-opsec/ --progress 2>/dev/null || true
fi
find /tmp -name "backup-*" -mtime +1 -delete 2>/dev/null || true
BEOF
chmod +x /usr/local/bin/backup-opsec.sh
if ! crontab -l 2>/dev/null | grep -q "backup-opsec"; then
  (crontab -l 2>/dev/null; echo "0 4 * * * /usr/local/bin/backup-opsec.sh >> /var/log/backup-opsec.log 2>&1 # backup-opsec") | crontab -
fi

#===============================================================================
# 9. RESUMO FINAL + PRÓXIMOS PASSOS
#===============================================================================
echo ""; echo "==============================================================================="
echo "  [🔥] DEPLOY CONCLUÍDO - STACK MINIMALISTA OPSEC v3.0"
echo "==============================================================================="
echo "  📁 FileBrowser:  http://127.0.0.1:8080  | user: admin | pass: $FB_PASS"
echo "  🌐 Caddy:        http://127.0.0.1:2015  (serve /var/www/html)"
echo "  🚇 Cloudflared:  INSTALADO (config em /etc/cloudflared/config.yml)"
echo ""
echo "  [⚠️]  SSH SAFETY: Mantém uma sessão aberta enquanto testa a nova!"
echo ""
echo "  [PRÓXIMOS PASSOS OBRIGATÓRIOS]"
echo "  1. Configura teu Cloudflare Tunnel:"
echo "     cloudflared tunnel login"
echo "     cloudflared tunnel create minimal-stack"
echo "     # Edita /etc/cloudflared/config.yml com teu tunnel ID e ingress"
echo "     cloudflared tunnel route dns minimal-stack teudominio.com"
echo "     cloudflared tunnel route dns minimal-stack files.teudominio.com"
echo "     systemctl enable --now cloudflared"
echo ""
echo "  2. No Cloudflare Dashboard:"
echo "     - SSL/TLS > Overview: Full (strict)"
echo "     - Sempre usa HTTPS: ✅"
echo "     - DNS records: ☁️ Proxied (nuvem laranja)"
echo ""
echo "  3. Testa localmente:"
echo "     curl -I -H 'Host: teudominio.com' http://127.0.0.1:2015"
echo "     curl -I -H 'Host: files.teudominio.com' http://127.0.0.1:8080"
echo ""
echo "  [OPSEC CHECKLIST]"
echo "  ✅ UFW: só localhost + teu IP liberado (SSH preservado)"
echo "  ✅ Caddy: auto_https OFF + bind explícito em 2015"
echo "  ✅ FileBrowser: --database flag correta + auth ativa"
echo "  ✅ Logs: rotação + limpeza automática"
echo "  ✅ IPv6: desativado"
echo "  ✅ Zero telemetria: stack open-source, auditável"
echo "==============================================================================="
log_info "Stack pronta. Agora é contigo, lek. 🔒"
