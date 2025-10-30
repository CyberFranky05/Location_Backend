#!/bin/bash

# Export Keycloak realm configuration
# Run this on EC2 where Keycloak is running

docker exec location-auth-keycloak /opt/keycloak/bin/kc.sh export \
  --dir /tmp/export \
  --realm location-auth-realm

# Copy exported file from container to host
docker cp location-auth-keycloak:/tmp/export/location-auth-realm-realm.json ./keycloak/realm-export.json

echo "✅ Realm exported to keycloak/realm-export.json"
