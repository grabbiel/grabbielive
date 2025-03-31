#!/bin/bash
# setup_server.sh

set -e # Exit on any error

echo "Setting up Grabbiel Server environment..."

# Update packages
sudo apt update
sudo apt install -y apache2 openssl libssl-dev g++ make

# Configure Apache
sudo a2enmod ssl rewrite proxy proxy_http proxy_https

# Create Apache config
cat >/tmp/grabbiel.com.conf <<'EOF'
<VirtualHost *:80>
    ServerName grabbiel.com
    ServerAlias www.grabbiel.com
    Redirect permanent / https://grabbiel.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName grabbiel.com
    ServerAlias www.grabbiel.com 
    DocumentRoot /var/www/grabbiel.com
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/server.grabbiel.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/server.grabbiel.com/privkey.pem
    
    ErrorLog ${APACHE_LOG_DIR}/grabbiel.com_error.log
    CustomLog ${APACHE_LOG_DIR}/grabbiel.com_access.log combined
    
    <Directory /var/www/grabbiel.com>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

# Create Apache config for API
cat >/tmp/server.grabbiel.com.conf <<'EOF'
<VirtualHost *:80>
    ServerName server.grabbiel.com
    Redirect permanent / https://server.grabbiel.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName server.grabbiel.com
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/server.grabbiel.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/server.grabbiel.com/privkey.pem
    
    # Forward API requests to the C++ server
    ProxyPass / https://localhost:8443/
    ProxyPassReverse / https://localhost:8443/
    
    # SSL Proxy configuration
    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    
    ErrorLog ${APACHE_LOG_DIR}/server.grabbiel.com_error.log
    CustomLog ${APACHE_LOG_DIR}/server.grabbiel.com_access.log combined
    
    # CORS Headers (if needed)
    Header always set Access-Control-Allow-Origin "https://grabbiel.com"
    Header always set Access-Control-Allow-Methods "GET, POST, OPTIONS"
    Header always set Access-Control-Allow-Headers "Content-Type, X-Requested-With, HX-Request, HX-Trigger, HX-Target, HX-Current-URL"
</VirtualHost>
EOF

sudo mv /tmp/grabbiel.com.conf /etc/apache2/sites-available/
sudo mv /tmp/server.grabbiel.com.conf /etc/apache2/sites-available

# Create web directories
sudo mkdir -p /var/www/grabbiel.com
sudo chown -R $USER:$USER /var/www/grabbiel.com

# Enable site
sudo a2ensite grabbiel.com.conf
sudo a2ensite server.grabbiel.com.conf

# Setup C++ server service
cat >/tmp/grabbiel-server.service <<'EOF'
[Unit]
Description=Grabbiel C++ Web Server
After=network.target

[Service]
ExecStart=/repo/server/server
WorkingDirectory=/repo/server
Restart=always
User=root
Group=root
Environment=PORT=8443

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/grabbiel-server.service /etc/systemd/system/

# Reload and restart services
sudo systemctl daemon-reload
sudo systemctl enable grabbiel-server
sudo systemctl restart grabbiel-server
sudo systemctl restart apache2

echo "Setup complete!"
