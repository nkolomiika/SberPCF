#!/bin/sh
# Runs from nginx's /docker-entrypoint.d before nginx starts.
# Generates a self-signed cert for localhost on first boot if none exists.
set -e

CERT_DIR=/etc/nginx/certs
CRT="$CERT_DIR/selfsigned.crt"
KEY="$CERT_DIR/selfsigned.key"

if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
    command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
        -keyout "$KEY" -out "$CRT" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    echo "nginx: generated self-signed certificate for localhost"
fi
