#!/bin/bash
# [Lek Do BlacK] - Deploy Minimalista OPSEC
# Uso: curl -sL https://raw.githubusercontent.com/teu-user/repo/main/deploy.sh | bash

set -e

# 1. Atualiza + limpa
apt update && apt upgrade -y
apt remove -y snapd lxd cloud-init* 2>/dev/null || true

# 2. Firewall básico
ufw default deny incoming
ufw default allow outgoing
ufw allow from 127.0.0.1 to any port 22,2015,8080
ufw enable

# 3. Instala Caddy
apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install -y caddy

# 4. Instala FileBrowser
curl -fsSL https://github.com/filebrowser/filebrowser/releases/latest/download/linux-amd64-filebrowser.tar.gz | tar xz
mv filebrowser /usr/local/bin/
chmod +x /usr/local/bin/filebrowser

# 5. Configura Caddy (reverse proxy + SSL local)
cat > /etc/caddy/Caddyfile << 'EOF'
:2015 {
    bind 127.0.0.1
    root * /var/www
    file_server
    encode gzip
}
EOF

# 6. Configura FileBrowser (sem auth por padrão - ADD AUTH DEPOIS)
filebrowser config init --address 127.0.0.1 --port 8080 --database /etc/filebrowser.db
filebrowser users add admin senha-forte-aqui --perm.admin

# 7. Cria serviços systemd
# [Caddy já tem serviço nativo]

# FileBrowser service
cat > /etc/systemd/system/filebrowser.service << 'EOF'
[Unit]
Description=FileBrowser
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/filebrowser --config /etc/filebrowser.db
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# 8. Inicia tudo
systemctl daemon-reload
systemctl enable --now caddy filebrowser

# 9. (Opcional) Instala cloudflared se não tiver
if ! command -v cloudflared &> /dev/null; then
    curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cf.deb
    dpkg -i /tmp/cf.deb
fi

echo "✅ Deploy concluído!"
echo "📁 FileBrowser: http://127.0.0.1:8080 (user: admin)"
echo "🌐 Caddy: http://127.0.0.1:2015"
echo "🔧 Próximo passo: configurar Cloudflare Tunnel"
