#!/bin/sh

# Nginx startup script that checks for SSL certificates
# and uses appropriate configuration

# Use environment variable or default
DOMAIN=${DOMAIN:-"mrelectron.xyz"}
CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
HTTPS_CONFIG="/etc/nginx/nginx-https.conf"
HTTP_CONFIG="/etc/nginx/nginx-http-only.conf"
ACTIVE_CONFIG="/etc/nginx/nginx.conf"

if [ -f "$CERT_PATH" ]; then
    echo "✅ SSL certificates found. Using HTTPS configuration."
    cp $HTTPS_CONFIG $ACTIVE_CONFIG
else
    echo "⚠️  SSL certificates not found. Using HTTP-only configuration."
    echo "Run certbot to obtain certificates, then restart nginx."
    cp $HTTP_CONFIG $ACTIVE_CONFIG
fi

# Test configuration
nginx -t

if [ $? -eq 0 ]; then
    echo "✅ Nginx configuration is valid. Starting nginx..."
    exec nginx -g 'daemon off;'
else
    echo "❌ Nginx configuration test failed!"
    exit 1
fi
