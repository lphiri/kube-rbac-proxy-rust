# Go/Rust benchmark harness

`compare.sh` builds both implementations, starts the same deterministic compiled
Go local upstream, and sends identical HTTP/1.1 workloads through each proxy. It reports
throughput, mean request latency, failed requests, and the proxy process's peak
resident set size (RSS).

Peak RSS uses Linux `/proc/<pid>/status` `VmHWM`, so the memory field requires
Linux. Throughput and latency collection uses ApacheBench on any platform where
`ab` is available.

Run from the Rust repository:

```sh
REQUESTS=10000 CONCURRENCY=32 WARMUP=200 bench/compare.sh
```

For a quick smoke test, use `REQUESTS=100 CONCURRENCY=4 WARMUP=10`. Use
`--no-build` when repeating a run with already-built binaries. Results append to
`bench/results.csv`, which is intentionally ignored by Git.

Set `KEEP_WORK_DIR=1` after a failure to retain ApacheBench output and proxy
logs for diagnosis.

Set `RUST_WORKER_THREADS` and `GO_MAX_PROCS` to the same value when comparing a
fixed worker budget. Leaving them unset uses Rust available-CPU workers and Go's
normal `GOMAXPROCS` default.

This is a proxy data-plane benchmark: requests use `--ignore-paths /benchmark`
and therefore exclude Kubernetes TokenReview/SAR, OIDC, client-certificate
verification, and TLS handshake costs. Run separate authenticated/TLS scenarios
when those costs are the subject of the comparison. Compare several repetitions
under low system load; do not treat one run as a statistically significant
result.

The Rust binary defaults to one Pingora worker unless configured otherwise in
older builds. Current builds use all available CPUs by default, matching Go's
normal `GOMAXPROCS` behavior; use `--worker-threads` for controlled experiments.
