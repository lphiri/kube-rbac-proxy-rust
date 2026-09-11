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

cat >"$WORK/h2c.go" <<'GO'
package main

import (
  "fmt"
  "net/http"
  "golang.org/x/net/http2"
  "golang.org/x/net/http2/h2c"
)

func main() {
  handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    _, _ = fmt.Fprintln(w, "h2c-ok")
  })
  server := &http.Server{Addr: "127.0.0.1:19445", Handler: h2c.NewHandler(handler, &http2.Server{})}
  if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed { panic(err) }
}
GO
(cd "$ROOT/../kube-rbac-proxy" && go run "$WORK/h2c.go") >/dev/null 2>&1 &
UPSTREAM_PID=$!

cargo build --quiet --locked
"$ROOT/target/debug/kube-rbac-proxy" \
  --upstream http://127.0.0.1:19445 --upstream-force-h2c \
  --secure-listen-address 127.0.0.1:18445 --ignore-paths '*' \
  >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 2
curl --fail --silent --show-error --insecure --http1.1 --max-time 5 \
  https://127.0.0.1:18445/h2c | grep -qx 'h2c-ok'
echo "h2c E2E passed: forced cleartext HTTP/2 upstream forwarding"
