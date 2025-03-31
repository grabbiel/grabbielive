#!/bin/bash
set -e # Exit on any error

echo "Setting up Grabbiel Server environment..."

# Determine what's using port 8443 and 80/443
echo "Checking for processes using required ports..."
PORT_8443_PID=$(sudo netstat -tulpn | grep ":8443" | awk '{print $7}' | cut -d'/' -f1)
PORT_80_PID=$(sudo netstat -tulpn | grep ":80" | awk '{print $7}' | cut -d'/' -f1)
PORT_443_PID=$(sudo netstat -tulpn | grep ":443" | awk '{print $7}' | cut -d'/' -f1)

# Stop processes if they exist
if [ ! -z "$PORT_8443_PID" ]; then
  echo "Process $PORT_8443_PID is using port 8443. Stopping..."
  sudo kill -15 $PORT_8443_PID || true
  sleep 2
  # If process still exists, force kill
  if ps -p $PORT_8443_PID >/dev/null; then
    sudo kill -9 $PORT_8443_PID || true
  fi
fi

# Stop Apache if it's running
sudo systemctl stop apache2 || true

# Clean up any existing service
echo "Stopping and removing existing grabbiel-server service..."
sudo systemctl stop grabbiel-server || true
sudo systemctl disable grabbiel-server || true

# Update packages
echo "Updating packages..."
sudo apt update
sudo apt install -y apache2 openssl libssl-dev g++ make

# Configure Apache
echo "Configuring Apache..."
sudo a2enmod ssl rewrite proxy proxy_http proxy_https headers

# Create Apache config for main site
echo "Creating Apache configuration..."
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

# Create Apache config for API server
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
    
    # CORS Headers
    Header always set Access-Control-Allow-Origin "https://grabbiel.com"
    Header always set Access-Control-Allow-Methods "GET, POST, OPTIONS"
    Header always set Access-Control-Allow-Headers "Content-Type, X-Requested-With, HX-Request, HX-Trigger, HX-Target, HX-Current-URL"
</VirtualHost>
EOF

sudo mv /tmp/grabbiel.com.conf /etc/apache2/sites-available/
sudo mv /tmp/server.grabbiel.com.conf /etc/apache2/sites-available/

# Create web directories
sudo mkdir -p /var/www/grabbiel.com
sudo chown -R $USER:$USER /var/www/grabbiel.com

# Enable sites
sudo a2ensite grabbiel.com.conf
sudo a2ensite server.grabbiel.com.conf
sudo a2dissite 000-default.conf

# Setup C++ server service
echo "Setting up C++ server service..."
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

# Compile the C++ server
echo "Compiling C++ server..."
cd /repo/server
sudo g++ -std=c++17 -I./include -o server server.cpp -lssl -lcrypto -pthread

# Create log directory
sudo mkdir -p /var/log/grabbiel-server
sudo chown root:root /var/log/grabbiel-server

# Reload and restart services
echo "Restarting services..."
sudo systemctl daemon-reload
sudo systemctl enable grabbiel-server
sudo systemctl restart grabbiel-server
sudo systemctl restart apache2

# Verify services are running
echo "Verifying services..."
sleep 2
sudo systemctl status grabbiel-server --no-pager
sudo systemctl status apache2 --no-pager
sudo netstat -tulpn | grep -E ':(80|443|8443)'

echo "Setup complete!"
