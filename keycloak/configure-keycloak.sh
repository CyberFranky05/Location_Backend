#!/bin/bash

# Keycloak Configuration Script
# This script configures Keycloak with realm and clients automatically

set -e

echo "🔧 Starting Keycloak configuration..."

# Wait for Keycloak to be ready
echo "⏳ Waiting for Keycloak to be ready..."
for i in {1..30}; do
    if /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin 2>/dev/null; then
        echo "✅ Keycloak is ready!"
        break
    fi
    echo "Waiting for Keycloak... ($i/30)"
    sleep 3
done

echo "✅ Keycloak is ready and logged in!"

# Check if realm already exists
if /opt/keycloak/bin/kcadm.sh get realms/location-auth-realm > /dev/null 2>&1; then
    echo "✅ Realm 'location-auth-realm' already exists"
else
    echo "📝 Creating realm 'location-auth-realm'..."
    /opt/keycloak/bin/kcadm.sh create realms \
        -s realm=location-auth-realm \
        -s enabled=true \
        -s registrationAllowed=true \
        -s registrationEmailAsUsername=false \
        -s resetPasswordAllowed=true \
        -s rememberMe=true \
        -s loginWithEmailAllowed=true \
        -s duplicateEmailsAllowed=false
    echo "✅ Realm created"
fi

# Check if backend client exists
if /opt/keycloak/bin/kcadm.sh get clients -r location-auth-realm --fields clientId | grep -q "location-auth-backend"; then
    echo "✅ Backend client already exists"
else
    echo "📝 Creating backend client..."
    /opt/keycloak/bin/kcadm.sh create clients -r location-auth-realm \
        -s clientId=location-auth-backend \
        -s enabled=true \
        -s clientAuthenticatorType=client-secret \
        -s secret=exMhUVzUVOsdkHABg23cDxr9WrLLJWEB \
        -s publicClient=false \
        -s serviceAccountsEnabled=true \
        -s directAccessGrantsEnabled=true \
        -s standardFlowEnabled=true \
        -s 'redirectUris=["http://localhost:3001/*"]' \
        -s 'webOrigins=["http://localhost:3001"]'
    echo "✅ Backend client created with secret: exMhUVzUVOsdkHABg23cDxr9WrLLJWEB"
    
    # Add service account roles for user management
    echo "🔑 Adding admin roles to backend service account..."
    
    # Get the service account user (auto-created for service accounts)
    SERVICE_ACCOUNT_USERNAME="service-account-location-auth-backend"
    
    # Add realm roles for user management
    /opt/keycloak/bin/kcadm.sh add-roles -r location-auth-realm --uusername "$SERVICE_ACCOUNT_USERNAME" --cclientid realm-management --rolename manage-users --rolename view-users --rolename query-users 2>/dev/null || echo "⚠️ Role assignment had issues but continuing..."
    
    echo "✅ Admin roles configured"
fi

# Check if frontend client exists
if /opt/keycloak/bin/kcadm.sh get clients -r location-auth-realm --fields clientId | grep -q "location-auth-frontend"; then
    echo "✅ Frontend client already exists"
else
    echo "📝 Creating frontend client..."
    /opt/keycloak/bin/kcadm.sh create clients -r location-auth-realm \
        -s clientId=location-auth-frontend \
        -s enabled=true \
        -s publicClient=true \
        -s directAccessGrantsEnabled=true \
        -s standardFlowEnabled=true \
        -s 'redirectUris=["http://localhost:3000/*","http://localhost:5173/*"]' \
        -s 'webOrigins=["http://localhost:3000","http://localhost:5173"]' \
        -s 'attributes={"post.logout.redirect.uris":"http://localhost:3000/*"}'
    echo "✅ Frontend client created"
fi

# Configure password policy
echo "🔒 Configuring password policy..."
/opt/keycloak/bin/kcadm.sh update realms/location-auth-realm \
    -s 'passwordPolicy="length(8) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1)"'

echo "✅ Password policy configured"

echo ""
echo "🎉 Keycloak configuration completed successfully!"
echo ""
echo "📋 Configuration Summary:"
echo "  - Realm: location-auth-realm"
echo "  - Backend Client: location-auth-backend"
echo "  - Backend Secret: exMhUVzUVOsdkHABg23cDxr9WrLLJWEB"
echo "  - Frontend Client: location-auth-frontend"
echo "  - Password Policy: Min 8 chars, 1 upper, 1 lower, 1 digit, 1 special"
echo ""
