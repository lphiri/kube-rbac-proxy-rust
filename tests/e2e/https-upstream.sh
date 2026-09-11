#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
UPSTREAM_PID=""
PROXY_PID=""
cleanup() {
  test -z "$PROXY_PID" || kill "$PROXY_PID" >/dev/null 2>&1 || true
  test -z "$UPSTREAM_PID" || kill "$UPSTREAM_PID" >/dev/null 2>&1 || true
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
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1') >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=proxy-client \
  -keyout "$WORK/client.key" -out "$WORK/client.csr" >/dev/null 2>&1
openssl x509 -req -in "$WORK/client.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
  -CAcreateserial -days 1 -out "$WORK/client.pem" \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth') >/dev/null 2>&1
UPSTREAM_DIR="$(mktemp -d /tmp/kube-rbac-proxy-https-upstream.XXXXXX)"
python3 - "$WORK" "$UPSTREAM_DIR" <<'PY' &
import http.server
import pathlib
import ssl
import sys
import time

certs = pathlib.Path(sys.argv[1])
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Length", "21")
            self.end_headers()
            for chunk in (b"chunk-1", b"chunk-2", b"chunk-3"):
                self.wfile.write(chunk)
                self.wfile.flush()
                time.sleep(0.2)
            return
        body = b"https-upstream-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 19443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certs / "server.pem", certs / "server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(cafile=certs / "ca.pem")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
UPSTREAM_PID=$!
sleep 1
cargo build --quiet --locked
RUST_LOG=debug "$ROOT/target/debug/kube-rbac-proxy" \
  --upstream https://localhost:19443 --upstream-ca-file "$WORK/ca.pem" \
  --upstream-client-cert-file "$WORK/client.pem" --upstream-client-key-file "$WORK/client.key" \
  --secure-listen-address 127.0.0.1:18443 --ignore-paths '*' \
  >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 2
if ! curl --fail --silent --show-error --insecure --http1.1 --max-time 5 \
  https://127.0.0.1:18443/hello | grep -qx 'https-upstream-ok'; then
  cat "$WORK/proxy.log"
  exit 1
fi
test "$(curl --fail --silent --show-error --insecure --http1.1 --max-time 5 \
  https://127.0.0.1:18443/stream | tr -d '\n')" = 'chunk-1chunk-2chunk-3'
echo "HTTPS upstream E2E passed: custom CA trust and forwarding"
