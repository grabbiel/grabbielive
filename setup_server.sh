#!/bin/bash

set -e

echo "=========== Installing dependencies ==========="
sudo apt update
sudo apt install -y g++ make openssl libssl-dev apache2

echo "=========== Building the C++ HTTPS server ==========="
cd /repo/server
g++ -std=c++17 server.cpp -o server -lssl -lcrypto -pthread

echo "=========== Setting up systemd service ==========="
sudo tee /etc/systemd/system/grabbiel-server.service >/dev/null <<EOF
[Unit]
Description=Grabbiel C++ HTTPS Server
After=network.target

[Service]
WorkingDirectory=/repo/server
ExecStart=/repo/server/server
Restart=on-failure
User=fcruzado22

[Install]
WantedBy=multi-user.target
EOF

echo "=========== Enabling and starting the server ==========="
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable grabbiel-server
sudo systemctl restart grabbiel-server

echo "=========== Configuring secure Apache reverse proxy ==========="

# Ensure required Apache modules are enabled
sudo a2enmod ssl proxy proxy_http headers

# Make sure Apache trusts backend hostname (loopback)
echo "127.0.0.1 server.grabbiel.com" | sudo tee -a /etc/hosts

# Create the Apache virtual host config
sudo tee /etc/apache2/sites-available/server.grabbiel.com.conf >/dev/null <<EOF
<VirtualHost *:443>
    ServerName server.grabbiel.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/server.grabbiel.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/server.grabbiel.com/privkey.pem

    ProxyPreserveHost On
    ProxyPass / https://server.grabbiel.com:8444/
    ProxyPassReverse / https://server.grabbiel.com:8444/

    SSLProxyEngine On
    SSLProxyVerify require
    SSLProxyCheckPeerCN on
    SSLProxyCheckPeerName on
    SSLProxyCheckPeerExpire on

    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-For %{REMOTE_ADDR}s
</VirtualHost>
EOF

# Enable site and reload Apache
sudo a2ensite server.grabbiel.com.conf
sudo systemctl reload apache2
sudo systemctl enable apache2

echo "=========== Setup complete ==========="
