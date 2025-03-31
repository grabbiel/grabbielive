#!/bin/bash
# setup_server.sh
set -e # Exit on any error

echo "Setting up Grabbiel Server environment..."

# Determine what's using port 8443 and 80/443
echo "Checking for processes using required ports..."
PORT_8443_PIDS=$(sudo lsof -i:8443 -t || true)
PORT_80_PIDS=$(sudo lsof -i:80 -t || true)
PORT_443_PIDS=$(sudo lsof -i:443 -t || true)

# Function to kill process and verify it's gone
kill_process() {
  local pid=$1
  echo "Stopping process $pid..."
  sudo kill -15 $pid 2>/dev/null || true
  sleep 2
  if ps -p $pid >/dev/null 2>&1; then
    echo "Process $pid still running, force killing..."
    sudo kill -9 $pid 2>/dev/null || true
    sleep 1
  fi
}

# Stop the C++ server service first if it exists
echo "Stopping and removing existing grabbiel-server service..."
sudo systemctl stop grabbiel-server 2>/dev/null || true
sudo systemctl disable grabbiel-server 2>/dev/null || true

# Find and kill any process named 'server' in /repo/server
echo "Checking for any running server processes..."
SERVER_PIDS=$(ps aux | grep "/repo/server/server" | grep -v grep | awk '{print $2}' || true)
if [ ! -z "$SERVER_PIDS" ]; then
  for pid in $SERVER_PIDS; do
    kill_process $pid
  done
fi

# Kill processes using ports
if [ ! -z "$PORT_8443_PIDS" ]; then
  for pid in $PORT_8443_PIDS; do
    kill_process $pid
  done
fi

# Final check - make sure port 8443 is free
echo "Verifying port 8443 is free..."
if [ ! -z "$(sudo lsof -i:8443 -t 2>/dev/null)" ]; then
  echo "ERROR: Port 8443 is still in use after cleanup attempts!"
  sudo lsof -i:8443
  exit 1
fi

# Update packages
echo "Updating packages..."
sudo apt update
sudo apt install -y apache2 openssl libssl-dev g++ make

# Configure Apache
echo "Configuring Apache..."
sudo a2enmod ssl || true
sudo a2enmod rewrite || true
sudo a2enmod proxy || true
sudo a2enmod proxy_http || true
sudo a2enmod headers || true

# Try to enable proxy_https if it exists (might not on some systems)
sudo a2enmod proxy_https 2>/dev/null || echo "Note: proxy_https module not available, continuing with proxy_http..."

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
sudo a2dissite 000-default.conf || true

# Setup C++ server service
echo "Setting up C++ server service..."
cat >/tmp/grabbiel-server.service <<'EOF'
[Unit]
Description=Grabbiel C++ Web Server
After=network.target

[Service]
ExecStart=/repo/server/server
WorkingDirectory=/repo/server
Restart=on-failure
User=root
Group=root
Environment=PORT=8443
RestartSec=5

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

# Stop Apache if it's running on port 80 or 443
if systemctl is-active --quiet apache2; then
  echo "Stopping Apache to free up ports..."
  sudo systemctl stop apache2
  sleep 2
fi

# Start Apache
echo "Starting Apache..."
sudo systemctl start apache2

# Verify services are running
echo "Verifying services..."
sleep 2

# Check C++ server
if sudo systemctl is-active --quiet grabbiel-server; then
  echo "✅ C++ server is running"
else
  echo "❌ C++ server failed to start"
  sudo systemctl status grabbiel-server
  exit 1
fi

# Check Apache
if sudo systemctl is-active --quiet apache2; then
  echo "✅ Apache is running"
else
  echo "❌ Apache failed to start"
  sudo systemctl status apache2
  exit 1
fi

# Verify ports
echo "Checking port usage..."
sudo netstat -tulpn | grep -E ':(80|443|8443)'

echo "Setup complete!"
