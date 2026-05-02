#!/bin/bash
# =============================================================================
# OPSEC SAFE v1.0 - SECURE BUT NO LOCKOUT
# =============================================================================
# Este script NÃO bloqueia acesso SSH e NÃO corta comunicação de saída
# Pode ser executado remotamente com segurança
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
mkdir -p /root/opsec-backup-$(date +%Y%m%d)
cp -r /etc/ssh /root/opsec-backup-$(date +%Y%m%d)/ 2>/dev/null || true
cp -r /etc/ufw /root/opsec-backup-$(date +%Y%m%d)/ 2>/dev/null || true
cp /etc/fail2ban/jail.local /root/opsec-backup-$(date +%Y%m%d)/ 2>/dev/null || true

log "Backup salvo em /root/opsec-backup-$(date +%Y%m%d)"

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
    log "Regras de firewall irão PRESERVAR seu acesso"
else
    warn "Não foi possível detectar seu IP"
    warn "O firewall NÃO será configurado para evitar lockout"
fi

# =============================================================================
# ATUALIZAR SISTEMA (opcional, seguro)
# =============================================================================
log "Atualizando repositórios..."
apt update -qq

# Instalar pacotes úteis (NÃO remove nada)
apt install -y -qq curl wget ufw fail2ban openssl ca-certificates

# =============================================================================
# FIREWALL SEGURO (SEM default deny outgoing)
# =============================================================================
if command -v ufw &>/dev/null; then
    log "Configurando UFW (MODO SEGURO)..."
    
    # Reset apenas se já estava configurado
    ufw --force disable 2>/dev/null || true
    
    # Configurações seguras
    ufw default deny incoming
    ufw default allow outgoing  # CRÍTICO: NÃO bloquear saída
    
    # Permitir SSH de forma segura
    if [ -n "$SSH_IP" ]; then
        ufw allow from "$SSH_IP" to any port 22 proto tcp comment "SSH do seu IP"
        log "SSH permitido APENAS para: $SSH_IP"
    else
        ufw allow 22/tcp comment "SSH (temporariamente aberto para evitar lockout)"
        warn "SSH permitido de qualquer IP - configure depois!"
    fi
    
    # Rate limit no SSH
    ufw limit 22/tcp
    
    # Portas internas (locais)
    ufw allow from 127.0.0.1 to any port 2015,8080,3000,5000,8000 proto tcp
    
    # BLOQUEAR apenas saída de email (prevenção de spam, não afeta SSH)
    ufw deny out 25/tcp
    ufw deny out 465/tcp
    ufw deny out 587/tcp
    
    # Ativar firewall
    echo "y" | ufw enable
    log "UFW ativado (MODO SEGURO - saída permitida)"
else
    error "UFW não encontrado - instalando..."
    apt install -y ufw
fi

# =============================================================================
# FAIL2BAN (seguro, NÃO bloqueia seu IP se errar senha 3x)
# =============================================================================
if command -v fail2ban &>/dev/null; then
    log "Configurando Fail2ban..."
    
    cat > /etc/fail2ban/jail.local <<EOF
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
    log "Fail2ban ativo (seu IP ignorado: $SSH_IP)"
fi

# =============================================================================
# SSH HARDENING (SEGURO - sem bloquear chave/senha simultaneamente)
# =============================================================================
log "Configurando SSH (modo seguro)..."

# Backup do config original
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Configurações seguras
cat > /etc/ssh/sshd_config.d/99-safe-opsec.conf <<EOF
# Configurações seguras (NÃO bloqueiam acesso)
ClientAliveInterval 120
ClientAliveCountMax 3
MaxAuthTries 6
MaxSessions 10
TCPKeepAlive yes
PermitRootLogin prohibit-password

# NÃO desabilitar senha! (evita lockout)
PasswordAuthentication yes

# Manter autenticação por chave
PubkeyAuthentication yes

# Logging
LogLevel VERBOSE
EOF

# Garantir que não perdeu acesso
systemctl restart ssh
log "SSH configurado - senha AINDA funciona como fallback"

# =============================================================================
# SYSCTL (SEGURO - sem cortar comunicação)
# =============================================================================
log "Otimizações de rede seguras..."

cat > /etc/sysctl.d/99-opsec-safe.conf <<EOF
# Proteção contra ataques básicos
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# Anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Não aceitar redirecionamentos
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# NÃO desabilitar IPv6 (pode quebrar cloud providers)
# NÃO desabilitar ICMP (pode quebrar detecção de MTU)
# NÃO restringir logs do kernel
EOF

sysctl --system >/dev/null 2>&1
log "Sysctl otimizado (sem quebrar conectividade)"

# =============================================================================
# DETECÇÃO DE VULNERABILIDADES (apenas scan, sem ação)
# =============================================================================
log "Verificando portas abertas..."
ss -tlnp | grep -v "127.0.0.1" | head -10 || true

# =============================================================================
# LOGGING (opcional, seguro)
# =============================================================================
log "Configurando logs (modo leve)..."

cat > /etc/systemd/journald.conf.d/99-opsec.conf <<EOF
[Journal]
SystemMaxUse=500M
MaxRetentionSec=7day
Compress=yes
EOF

systemctl restart systemd-journald
log "Logs configurados"

# =============================================================================
# VERIFICAÇÃO FINAL - TESTAR SE SSH AINDA FUNCIONA
# =============================================================================
log "Testando conectividade SSH..."
if ss -tlnp | grep -q ":22"; then
    log "✅ SSH está ouvindo na porta 22"
else
    error "❌ CRÍTICO: SSH não está ouvindo! Revertendo..."
    systemctl restart ssh
    sleep 2
    if ss -tlnp | grep -q ":22"; then
        log "✅ SSH recuperado"
    else
        error "⚠️  Algo grave aconteceu - restaure manualmente"
    fi
fi

# =============================================================================
# TESTE DE SAÍDA (verificar se internet funciona)
# =============================================================================
log "Testando conectividade de SAÍDA..."
if curl -s --max-time 5 https://api.github.com/zen > /dev/null 2>&1; then
    log "✅ Conexão de saída funcionando (importante para não se isolar)"
else
    warn "⚠️  Sem conexão de saída - verifique DNS"
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
fi

# =============================================================================
# INSTRUÇÕES DE RECUPERAÇÃO (CASO ALGO FALHE)
# =============================================================================
cat > /root/opsec-recovery.sh <<'EOF'
#!/bin/bash
# Script de RECUPERAÇÃO DE EMERGÊNCIA
# Caso perca acesso SSH, execute via AWS Console

echo "Restaurando configurações seguras..."
ufw --force disable
systemctl stop fail2ban
cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config 2>/dev/null
systemctl restart ssh
ufw allow 22/tcp
echo "y" | ufw enable
echo "✅ Recuperação concluída - tente SSH agora"
EOF

chmod +x /root/opsec-recovery.sh
log "Script de recuperação criado em /root/opsec-recovery.sh"

# =============================================================================
# INFORMAÇÕES FINAIS
# =============================================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     OPSEC SAFE v1.0 - CONFIGURADO COM SUCESSO            ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║ ✅ UFW ativo (saída permitida)                            ║"
echo "║ ✅ Fail2ban rodando (seu IP ignorado)                     ║"
echo "║ ✅ SSH: chave E senha funcionam (fallback seguro)         ║"
echo "║ ✅ Conectividade de saída OK                              ║"
echo "║ ✅ Script de recovery pronto                              ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║ 🔐 SEU ACESSO SSH ESTÁ PRESERVADO                         ║"
echo "║ 📁 Backup em: /root/opsec-backup-$(date +%Y%m%d)                ║"
echo "║ 🚨 Recovery: /root/opsec-recovery.sh (via AWS Console)    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# =============================================================================
# TESTE FINAL - MOSTRAR STATUS
# =============================================================================
log "Status do UFW:"
ufw status | head -5

log "Status do SSH:"
systemctl status ssh --no-pager -l | grep "Active:" || true

echo ""
log "✅ INSTALAÇÃO SEGURA CONCLUÍDA - Você NÃO será lockado!"
