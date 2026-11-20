#!/usr/bin/env bash
# Writes .env with fresh 256-bit secrets from OpenSSL's CSPRNG.
# Usage: bash scripts/gen_secrets.sh [--force]
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env && "${1:-}" != "--force" ]]; then
    echo "[!] .env already exists. Re-run with --force to overwrite (this invalidates sessions, audit chain and encrypted TOTP secrets)."
    exit 1
fi

cat > .env <<EOF
GHOSTLINE_CONFIG=development

# Flask secret (CSRF tokens, signed cookies)
SECRET_KEY=$(openssl rand -hex 32)
# HMAC-SHA256 key for the tamper-evident audit chain
AUDIT_HMAC_KEY=$(openssl rand -hex 32)
# AES-256-GCM key for server-side encryption at rest (TOTP secrets)
DATA_ENC_KEY=$(openssl rand -hex 32)
# HMAC key used to derive fake KDF salts for unknown usernames (anti-enumeration)
PRELOGIN_SALT_KEY=$(openssl rand -hex 32)

HOST=127.0.0.1
PORT=5443
EOF

chmod 600 .env 2>/dev/null || true
echo "[+] .env written with fresh secrets."
