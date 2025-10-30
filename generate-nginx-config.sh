#!/bin/bash

# Generate nginx configuration from template
# This script replaces environment variables in the nginx template

set -e

echo "Generating nginx configuration..."

# Source the .env file
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Error: .env file not found"
    exit 1
fi

# Set defaults if not provided
: ${BACKEND_PORT:=3000}
: ${KEYCLOAK_PORT:=8080}
: ${VERCEL_FRONTEND_URL:=https://location-frontend-murex.vercel.app}

# Generate nginx.conf from template
envsubst '${BACKEND_PORT} ${KEYCLOAK_PORT} ${VERCEL_FRONTEND_URL}' \
    < nginx/nginx.backend.http.conf.template \
    > nginx/nginx.backend.conf

echo "nginx configuration generated successfully!"
echo "Backend Port: ${BACKEND_PORT}"
echo "Keycloak Port: ${KEYCLOAK_PORT}"
echo "Frontend URL: ${VERCEL_FRONTEND_URL}"
