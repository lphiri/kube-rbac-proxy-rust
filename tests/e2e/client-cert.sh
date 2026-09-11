#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
UPSTREAM_PID=""
PROXY_PID=""
UPSTREAM_DIR=""
cleanup() {
  test -z "$PROXY_PID" || kill "$PROXY_PID" >/dev/null 2>&1 || true
  test -z "$UPSTREAM_PID" || kill "$UPSTREAM_PID" >/dev/null 2>&1 || true
  test -z "$UPSTREAM_DIR" || rm -rf "$UPSTREAM_DIR"
  rm -rf "$WORK"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=e2e-ca \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$WORK/server.key" -out "$WORK/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
  -CAcreateserial -days 1 -out "$WORK/server.pem" \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1') >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=e2e-client \
  -keyout "$WORK/client.key" -out "$WORK/client.csr" >/dev/null 2>&1
openssl x509 -req -in "$WORK/client.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
  -CAcreateserial -days 1 -out "$WORK/client.pem" \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth') >/dev/null 2>&1
printf '%s\n' 'authorization:' '  resourceAttributes:' '    apiVersion: v1' '    resource: pods' '    namespace: e2e' '    verb: get' '  static:' '  - user:' '      name: e2e-client' '    resourceRequest: true' '    resource: pods' '    namespace: e2e' '    verb: get' >"$WORK/auth.yaml"

UPSTREAM_DIR="$(mktemp -d /tmp/kube-rbac-proxy-upstream.XXXXXX)"
python3 -m http.server 19443 --bind 127.0.0.1 --directory "$UPSTREAM_DIR" >/dev/null 2>&1 &
UPSTREAM_PID=$!
cargo build --quiet --locked
"$ROOT/target/debug/kube-rbac-proxy" \
  --upstream http://127.0.0.1:19443 \
  --secure-listen-address 127.0.0.1:18443 \
  --tls-cert-file "$WORK/server.pem" --tls-private-key-file "$WORK/server.key" \
  --client-ca-file "$WORK/ca.pem" --config-file "$WORK/auth.yaml" \
  >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 1

if curl --silent --insecure --http1.1 --max-time 3 https://127.0.0.1:18443/ >/dev/null 2>&1; then
  echo "client certificate was not required" >&2
  exit 1
fi
curl --fail --silent --show-error --cacert "$WORK/ca.pem" --cert "$WORK/client.pem" \
  --key "$WORK/client.key" --http1.1 --max-time 5 https://127.0.0.1:18443/ | grep -q '<!DOCTYPE HTML>'
echo "Client certificate E2E passed: mTLS verification, CN identity, static authorization, and forwarding"
