# Keycloak production Docker image
FROM quay.io/keycloak/keycloak:23.0 AS builder

# Enable health and metrics
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Configure database vendor
ENV KC_DB=postgres

# Build optimized Keycloak
WORKDIR /opt/keycloak
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:23.0

# Copy built artifacts from builder
COPY --from=builder /opt/keycloak/ /opt/keycloak/

# Non-root user
USER 1000

# Production environment variables
ENV KC_HOSTNAME=mrelectron.xyz
ENV KC_HOSTNAME_STRICT=false
ENV KC_HTTP_ENABLED=true
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_DB=postgres

# Expose ports
EXPOSE 8080
EXPOSE 8443

# Start Keycloak in production mode
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
