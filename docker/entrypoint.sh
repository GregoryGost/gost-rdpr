#!/bin/bash
set -e

echo "Starting GOST RDPR with UI..."
echo "================================"

# Checking for static files
if [ ! -f "/var/www/html/index.html" ]; then
  echo "ERROR: UI static files not found in /var/www/html"
  exit 1
fi

# Checking for the presence of a Python application
if [ ! -f "/app/main.py" ]; then
  echo "ERROR: Python application not found in /app"
  exit 1
fi

# Creating the necessary directories (runtime setup)
# Created here, not in the Dockerfile, for:
# - Compatibility with volume mounts
# - Setting the correct permissions before starting services
mkdir -p /app/db /var/log/supervisor /run/nginx /var/log/nginx

# Setting the correct access rights
chown -R www-data:www-data /var/www/html
chown -R www-data:www-data /var/log/nginx

# Testing nginx configuration
echo "Testing nginx configuration..."
nginx -t

if [ $? -eq 0 ]; then
  echo "✓ Nginx configuration is valid"
else
  echo "✗ Nginx configuration test failed"
  exit 1
fi

echo "================================"
echo "Starting services via supervisor..."
echo "- Nginx on port 8080 (Web UI + API proxy)"
echo "- Python API on port 4000 (internal)"
echo "================================"

# Start supervisord
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
