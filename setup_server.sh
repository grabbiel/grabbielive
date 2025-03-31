#!/bin/bash
# setup_server.sh
set -e # Exit on any error

echo "Setting up Grabbiel Server environment..."

# Install required tools first
echo "Installing required tools..."
sudo apt update
sudo apt install -y lsof apache2 openssl libssl-dev g++ make

# Check for conflicting API server
echo "Checking for conflicting api_server process..."
API_SERVER_PID=$(ps aux | grep "/repo/api-server/api_server" | grep -v grep | awk '{print $2}' || true)
if [ ! -z "$API_SERVER_PID" ]; then
  echo "Found conflicting api_server process (PID: $API_SERVER_PID). Stopping..."
  sudo kill -15 $API_SERVER_PID || true
  sleep 2
  # If still running, force kill
  if ps -p $API_SERVER_PID >/dev/null 2>&1; then
    sudo kill -9 $API_SERVER_PID || true
  fi
fi

# Stop the C++ server service first if it exists
echo "Stopping and removing existing grabbiel-server service..."
sudo systemctl stop grabbiel-server 2>/dev/null || true
sudo systemctl disable grabbiel-server 2>/dev/null || true

# Find and kill any process named 'server' in /repo/server
echo "Checking for any running server processes..."
SERVER_PIDS=$(ps aux | grep "/repo/server/server" | grep -v grep | awk '{print $2}' || true)
if [ ! -z "$SERVER_PIDS" ]; then
  for pid in $SERVER_PIDS; do
    echo "Stopping process $pid..."
    sudo kill -15 $pid 2>/dev/null || true
    sleep 1
  done
fi

# Configure Apache
echo "Configuring Apache..."
sudo a2enmod ssl || true
sudo a2enmod rewrite || true
sudo a2enmod proxy || true
sudo a2enmod proxy_http || true
sudo a2enmod headers || true
sudo a2enmod env || true

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

# Create Apache config for API server - USING PORT 8444
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
    
    # Enable CORS headers - these must come before ProxyPass directives
    Header always set Access-Control-Allow-Origin "https://grabbiel.com"
    Header always set Access-Control-Allow-Methods "GET, POST, OPTIONS"
    Header always set Access-Control-Allow-Headers "Content-Type, X-Requested-With, HX-Request, HX-Trigger, HX-Target, HX-Current-URL"
    Header always set Access-Control-Max-Age "3600"
    
    # Special handling for OPTIONS requests
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} OPTIONS
    RewriteRule ^(.*)$ $1 [R=200,L]
    
    # Forward API requests to the C++ server
    ProxyPass / https://localhost:8444/
    ProxyPassReverse / https://localhost:8444/
    
    # SSL Proxy configuration
    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    
    # Log configuration with debug level for troubleshooting
    LogLevel debug
    ErrorLog ${APACHE_LOG_DIR}/server.grabbiel.com_error.log
    CustomLog ${APACHE_LOG_DIR}/server.grabbiel.com_access.log combined
</VirtualHost>
EOF

# Create specific CORS configuration
cat >/tmp/cors.conf <<'EOF'
<IfModule mod_headers.c>
    SetEnvIf Origin "^(https://grabbiel\.com)$" CORS_ALLOW_ORIGIN=$1
    Header set Access-Control-Allow-Origin %{CORS_ALLOW_ORIGIN}e env=CORS_ALLOW_ORIGIN
    Header set Access-Control-Allow-Methods "GET, POST, OPTIONS" env=CORS_ALLOW_ORIGIN
    Header set Access-Control-Allow-Headers "Content-Type, X-Requested-With, HX-Request, HX-Trigger, HX-Target, HX-Current-URL" env=CORS_ALLOW_ORIGIN
    Header set Access-Control-Max-Age "3600" env=CORS_ALLOW_ORIGIN
    
    # Always respond successfully to OPTIONS requests
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} OPTIONS
    RewriteRule ^(.*)$ $1 [R=200,L]
</IfModule>
EOF

sudo mv /tmp/grabbiel.com.conf /etc/apache2/sites-available/
sudo mv /tmp/server.grabbiel.com.conf /etc/apache2/sites-available/
sudo mv /tmp/cors.conf /etc/apache2/conf-available/

# Create web directories
sudo mkdir -p /var/www/grabbiel.com
sudo chown -R $USER:$USER /var/www/grabbiel.com

# Enable configurations
sudo a2ensite grabbiel.com.conf
sudo a2ensite server.grabbiel.com.conf
sudo a2enconf cors
sudo a2dissite 000-default.conf || true

# Setup C++ server service - USING PORT 8444
echo "Setting up C++ server service..."
cat >/tmp/grabbiel-server.service <<'EOF'
[Unit]
Description=Grabbiel C++ Web Server
After=network.target
Conflicts=api_server.service

[Service]
ExecStart=/repo/server/server
WorkingDirectory=/repo/server
Restart=on-failure
User=root
Group=root
Environment=PORT=8444
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/grabbiel-server.service /etc/systemd/system/

# Add CORS headers in the C++ server code as well (modify server.cpp)
echo "Adding CORS headers to C++ server responses..."
if ! grep -q "Access-Control-Allow-Origin" /repo/server/server.cpp; then
  echo "CORS headers not found in server.cpp, this is handled by Apache proxy."
fi

# Add diagnostic logging to check port usage
echo "Adding diagnostic logging to check port usage..."
cat >>/repo/server/diagnostic.log <<'EOF'
Checking active network connections:
EOF
sudo ss -tulpn >>/repo/server/diagnostic.log 2>&1

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

# Test CORS with curl
echo "Testing CORS configuration..."
sleep 2
curl -I -H "Origin: https://grabbiel.com" -X OPTIONS https://localhost:8444/me || echo "CORS test to C++ server failed (expected if curl isn't installed)"

# Verify services are running
echo "Verifying services..."
sleep 3

# Check C++ server
if sudo systemctl is-active --quiet grabbiel-server; then
  echo "✅ C++ server is running"
else
  echo "❌ C++ server failed to start"
  sudo systemctl status grabbiel-server
  echo "Checking server logs..."
  sudo tail -n 20 /var/log/grabbiel-server.log
  echo "Checking network status..."
  sudo ss -tulpn | grep -E ':(8443|8444)'
  exit 1
fi

# Start Apache
echo "Starting Apache..."
sudo systemctl restart apache2

# Check Apache
if sudo systemctl is-active --quiet apache2; then
  echo "✅ Apache is running"
else
  echo "❌ Apache failed to start"
  sudo systemctl status apache2
  exit 1
fi

echo "Setup complete! C++ server is running on port 8444 and Apache is configured with proper CORS headers."

echo "========== Setting up Apache Reverse Proxy =========="

# Install Apache and required modules
sudo apt update
sudo apt install -y apache2
sudo a2enmod ssl proxy proxy_http headers

# Create the reverse proxy config
cat <<EOF | sudo tee /etc/apache2/sites-available/server.grabbiel.com.conf
<VirtualHost *:443>
    ServerName server.grabbiel.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/server.grabbiel.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/server.grabbiel.com/privkey.pem

    ProxyPreserveHost On
    ProxyPass / https://localhost:8444/
    ProxyPassReverse / https://localhost:8444/

    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-For %{REMOTE_ADDR}s
</VirtualHost>
EOF

# Enable the new site
sudo a2ensite server.grabbiel.com.conf

# Reload Apache to apply changes
sudo systemctl reload apache2

# Enable Apache to run at boot
sudo systemctl enable apache2

echo "========== Apache Reverse Proxy Configured =========="
