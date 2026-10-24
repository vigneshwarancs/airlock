# Benchmarks

Airlock is on the hot path of every token, so the cost it adds has to be
measurable and small. This page records what is actually measured today, and
is explicit about what is not.

Reproduce with:

```bash
make bench
```

## Measured: the streaming rehydrator

`internal/rewrite` is the component with a real algorithmic risk — it inspects
every byte of every response and holds back ambiguous tails.

Run on an Apple M-series laptop, `go1.21`, `darwin/arm64`:

| Benchmark | ns/op | throughput | allocs/op |
|---|---:|---:|---:|
| `BenchmarkRehydratePlainText` — one pass, no placeholders | 877 | 5.8 GB/s | 2 |
| `BenchmarkRehydrateStreamed` — 16-byte chunks, placeholders present | 17,324 | 162 MB/s | 201 |

Read these as the two ends of the range. Plain prose with nothing to restore
costs essentially one scan. The streamed case pays per chunk, which is the
realistic shape for token-by-token SSE: ~200 allocations for a 2.8 KB response
delivered in 16-byte pieces.

For context, a model emitting 100 tokens/second produces roughly 400 bytes/s.
At 162 MB/s the rehydrator is about six orders of magnitude faster than the
stream it is inspecting — it is not the bottleneck.

### Why the hold is bounded

The rehydrator never withholds more than `vault.MaxPlaceholderLen` (64) bytes,
so the latency it adds to any single chunk is bounded rather than amortized.
`TestHoldIsBounded` enforces this.

## Not yet measured

Honest gaps, each one a task rather than a claim:

- **End-to-end proxy latency.** The README's targets (p50 < 2 ms non-streaming,
  added TTFT < 5 ms) are design budgets, not measurements. They need a
  benchmark that drives the full `internal/proxy` handler against a local
  upstream.
- **Detector scan cost** on large request bodies. A 100 KB prompt runs every
  enabled regex; that cost scales with the detector count and is currently
  unquantified.
- **Throughput under concurrency.** Single-core request/s has not been
  measured.

No performance numbers are claimed in the README beyond what appears on this
page.
