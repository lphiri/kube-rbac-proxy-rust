#!/usr/bin/env bash
set -euo pipefail

# Compare the two binaries on the same host and against the same local upstream.
# This measures proxy overhead, not Kubernetes API latency or TLS handshakes.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUST_REPO="$(cd -- "$SCRIPT_DIR/.." && pwd)"
GO_REPO="${GO_REPO:-$RUST_REPO/../kube-rbac-proxy}"
REQUESTS="${REQUESTS:-10000}"
CONCURRENCY="${CONCURRENCY:-32}"
WARMUP="${WARMUP:-200}"
OUTPUT="${OUTPUT:-$RUST_REPO/bench/results.csv}"
RUST_BINARY="${RUST_BINARY:-$RUST_REPO/target/release/kube-rbac-proxy}"
GO_BINARY="${GO_BINARY:-$GO_REPO/bin/kube-rbac-proxy-bench}"
UPSTREAM_PORT="${UPSTREAM_PORT:-19090}"

usage() {
    cat <<'EOF'
Usage: bench/compare.sh [options]

Environment variables control the run:
  REQUESTS=10000 CONCURRENCY=32 WARMUP=200
  GO_REPO=../kube-rbac-proxy RUST_BINARY=... GO_BINARY=...
  OUTPUT=bench/results.csv

Options:
  --no-build  Use existing binaries instead of building both implementations.
  --help      Show this help.
EOF
}

BUILD=1
while (($#)); do
    case "$1" in
        --no-build) BUILD=0; shift ;;
        --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

command -v ab >/dev/null || { echo "ab is required (apachebench)" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v go >/dev/null || { echo "go is required to build the Go binary" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo is required to build the Rust binary" >&2; exit 1; }

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kube-rbac-proxy-bench.XXXXXX")"
UPSTREAM_PID=""
PROXY_PID=""
cleanup() {
    if [[ -n "$PROXY_PID" ]]; then kill "$PROXY_PID" >/dev/null 2>&1 || true; wait "$PROXY_PID" >/dev/null 2>&1 || true; fi
    if [[ -n "$UPSTREAM_PID" ]]; then kill "$UPSTREAM_PID" >/dev/null 2>&1 || true; wait "$UPSTREAM_PID" >/dev/null 2>&1 || true; fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if ((BUILD)); then
    (cd "$RUST_REPO" && cargo build --release --locked)
    (cd "$GO_REPO" && go build -o "$GO_BINARY" ./cmd/kube-rbac-proxy)
fi
[[ -x "$RUST_BINARY" ]] || { echo "Rust binary not executable: $RUST_BINARY" >&2; exit 1; }
[[ -x "$GO_BINARY" ]] || { echo "Go binary not executable: $GO_BINARY" >&2; exit 1; }

python3 "$SCRIPT_DIR/upstream.py" --port "$UPSTREAM_PORT" >"$WORK_DIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!
for _ in $(seq 1 50); do
    if curl --silent --fail "http://127.0.0.1:$UPSTREAM_PORT/benchmark" >/dev/null; then break; fi
    sleep 0.1
done
curl --silent --fail "http://127.0.0.1:$UPSTREAM_PORT/benchmark" >/dev/null

# Both implementations initialize their Kubernetes clients during startup even
# when every benchmark request is bypassed. Point them at an inert local endpoint
# so this benchmark measures the data plane without requiring a cluster.
cat >"$WORK_DIR/kubeconfig" <<EOF
apiVersion: v1
kind: Config
current-context: benchmark
clusters:
- name: benchmark
  cluster:
    server: http://127.0.0.1:9
users:
- name: benchmark
  user:
    token: benchmark-token
contexts:
- name: benchmark
  context:
    cluster: benchmark
    user: benchmark
EOF

mkdir -p "$(dirname -- "$OUTPUT")"
if [[ ! -s "$OUTPUT" ]]; then
    echo "timestamp,implementation,requests,concurrency,requests_per_second,mean_latency_ms,failed_requests,max_rss_kb" >"$OUTPUT"
fi

run_one() {
    local name="$1" binary="$2" port="$3"
    local load_file="$WORK_DIR/$name.ab" log_file="$WORK_DIR/$name.log"
    "$binary" \
        --upstream "http://127.0.0.1:$UPSTREAM_PORT" \
        --kubeconfig "$WORK_DIR/kubeconfig" \
        --insecure-listen-address "127.0.0.1:$port" \
        --ignore-paths /benchmark \
        >"$log_file" 2>&1 &
    PROXY_PID=$!
    for _ in $(seq 1 50); do
        if curl --silent --fail "http://127.0.0.1:$port/benchmark" >/dev/null; then break; fi
        sleep 0.1
    done
    curl --silent --fail "http://127.0.0.1:$port/benchmark" >/dev/null
    ab -n "$WARMUP" -c "$CONCURRENCY" -q "http://127.0.0.1:$port/benchmark" >/dev/null

    kill "$PROXY_PID" >/dev/null 2>&1 || true
    wait "$PROXY_PID" >/dev/null 2>&1 || true
    PROXY_PID=""
    "$binary" \
        --upstream "http://127.0.0.1:$UPSTREAM_PORT" \
        --kubeconfig "$WORK_DIR/kubeconfig" \
        --insecure-listen-address "127.0.0.1:$port" \
        --ignore-paths /benchmark \
        >"$log_file" 2>&1 &
    PROXY_PID=$!
    for _ in $(seq 1 50); do
        if curl --silent --fail "http://127.0.0.1:$port/benchmark" >/dev/null; then break; fi
        sleep 0.1
    done
    ab -n "$REQUESTS" -c "$CONCURRENCY" -q "http://127.0.0.1:$port/benchmark" >"$load_file"
    # Linux exposes VmHWM (the process's peak resident set size) in kB.
    local rss
    rss="$(awk '/^VmHWM:/ {print $2; exit}' "/proc/$PROXY_PID/status")"
    kill "$PROXY_PID" >/dev/null 2>&1 || true
    wait "$PROXY_PID" >/dev/null 2>&1 || true
    PROXY_PID=""

    local rps latency failed
    rps="$(awk '/Requests per second:/ {print $4; exit}' "$load_file")"
    latency="$(awk '/Time per request:/ {print $4; exit}' "$load_file")"
    failed="$(awk '/Failed requests:/ {print $3; exit}' "$load_file")"
    [[ "$failed" == "0" ]] || { echo "$name had $failed failed requests" >&2; return 1; }
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$name" "$REQUESTS" "$CONCURRENCY" \
        "$rps" "$latency" "$failed" "$rss" >>"$OUTPUT"
    printf '%-5s requests/sec=%-10s mean_ms=%-8s peak_rss_kb=%s\n' "$name" "$rps" "$latency" "$rss"
}

echo "Benchmark: $REQUESTS requests, concurrency $CONCURRENCY, warmup $WARMUP"
run_one go "$GO_BINARY" 18080
run_one rust "$RUST_BINARY" 18081
echo "Results appended to $OUTPUT"
