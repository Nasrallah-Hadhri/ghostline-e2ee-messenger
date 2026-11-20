#!/usr/bin/env bash
# GhostLine PKI bootstrap (OpenSSL):
#   1. Local root CA (ECDSA P-256)        -> certs/ca.crt, certs/ca.key
#   2. TLS server cert signed by that CA  -> certs/server.crt, certs/server.key
#   3. Ed25519 key that signs the public-key directory -> certs/signing_ed25519.{key,pub}
#
# Usage: bash scripts/gen_certs.sh [--force]
set -euo pipefail

# Git Bash on Windows rewrites "/CN=..." into a file path; disable that.
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/.."
DIR=certs
mkdir -p "$DIR"

if [[ -f "$DIR/ca.crt" && "${1:-}" != "--force" ]]; then
    echo "[!] $DIR/ca.crt already exists. Re-run with --force to regenerate everything."
    exit 1
fi

echo "[*] Generating root CA (P-256, 5 years)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DIR/ca.key"
openssl req -x509 -new -key "$DIR/ca.key" -sha256 -days 1825 \
    -subj "/CN=GhostLine Root CA/O=GhostLine/C=TN" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$DIR/ca.crt"

echo "[*] Generating server key + CSR"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DIR/server.key"
openssl req -new -key "$DIR/server.key" \
    -subj "/CN=localhost/O=GhostLine/C=TN" \
    -out "$DIR/server.csr"

cat > "$DIR/server.ext" <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:ghostline.local, IP:127.0.0.1
EOF

echo "[*] Signing server certificate with the CA (397 days, browser max)"
openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
    -CAcreateserial -days 397 -sha256 -extfile "$DIR/server.ext" \
    -out "$DIR/server.crt"
rm -f "$DIR/server.csr" "$DIR/server.ext"

echo "[*] Verifying the chain"
openssl verify -CAfile "$DIR/ca.crt" "$DIR/server.crt"

echo "[*] Generating Ed25519 key-directory signing key"
openssl genpkey -algorithm ed25519 -out "$DIR/signing_ed25519.key"
openssl pkey -in "$DIR/signing_ed25519.key" -pubout -out "$DIR/signing_ed25519.pub"

chmod 600 "$DIR"/*.key 2>/dev/null || true

echo
echo "[+] Done. Import $DIR/ca.crt into your browser / OS trust store"
echo "    (Windows: double-click ca.crt -> Install -> Local Machine -> Trusted Root Certification Authorities)."
openssl x509 -in "$DIR/server.crt" -noout -subject -issuer -dates -ext subjectAltName
