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
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost') >/dev/null 2>&1
cat >"$WORK/h2.go" <<'GO'
package main

import (
  "crypto/tls"
  "fmt"
  "net/http"
  "os"
  "golang.org/x/net/http2"
)

func main() {
  handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprintln(w, r.Proto) })
  server := &http.Server{Addr: "127.0.0.1:19446", Handler: handler}
  if err := http2.ConfigureServer(server, &http2.Server{}); err != nil { panic(err) }
  certificate, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2]); if err != nil { panic(err) }
  server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}}
  if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed { panic(err) }
}
GO
(cd "$ROOT/../kube-rbac-proxy" && go run "$WORK/h2.go" "$WORK/server.pem" "$WORK/server.key") >/dev/null 2>&1 &
UPSTREAM_PID=$!
sleep 2
cargo build --quiet --locked
"$ROOT/target/debug/kube-rbac-proxy" \
  --upstream https://localhost:19446 --upstream-ca-file "$WORK/ca.pem" \
  --secure-listen-address 127.0.0.1:18446 --ignore-paths '*' \
  >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 2
if ! response="$(curl --fail --silent --show-error --insecure --http2 --max-time 5 \
  https://127.0.0.1:18446/)"; then
  cat "$WORK/proxy.log"
  exit 1
fi
test "$response" = 'HTTP/2.0'
echo "HTTPS upstream HTTP/2 E2E passed"
