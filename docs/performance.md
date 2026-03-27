---
layout: default
title: Performance
nav_order: 5
---

# Performance

## Benchmarks

All measurements taken with `ReleaseFast` optimization on Linux x86_64.

### Per-file scan time

| Metric | Measured |
|--------|----------|
| Single file, 20 rules | **332 μs** |
| Parse only (tree-sitter) | 173 μs |
| Indexed match only (SIMD) | 8.9 μs |
| Startup time | ~1 ms |
| Binary size | 2.7 MB |

### Real-world: Mozilla pdf.js

429 JavaScript files, 204K lines of code, 10 security rules.

| | Zentinel | Semgrep |
|---|---|---|
| Cold scan | **2.4s** | 7.6s |
| Warm scan (cached) | **37ms** | 7.6s |
| Findings | 80 | 73 |

Zentinel finds more issues in less time. Warm scans are **204x faster**.

### Micro-benchmark: per-file comparison

Same file, same 20 rules, full pipeline (parse + normalize + match).

| | Zentinel | Semgrep |
|---|---|---|
| Time per scan | **332 μs** | 1,562 ms |
| Speedup | **4,704x** | baseline |
| Findings | 21 | 21 |

Both tools find identical findings. Zentinel does it in microseconds.

## Why it's fast

### Indexed matching

Rules are compiled into a dispatch table keyed by atom hash. Instead of scanning all nodes once per rule (O(nodes x rules)), the engine scans nodes once with O(1) lookup per node.

| Matcher | Time/iter | Speedup |
|---------|-----------|---------|
| Linear scan | 179 μs | 1x |
| Indexed + SIMD | **8.9 μs** | **20x** |

### SIMD hash comparison

The dispatch table uses 64-bit Wyhash for atom keys. A 4-wide SIMD vector compares 4 rule hashes per CPU cycle.

### Parent-child index

A precomputed adjacency list maps `parent_id → [child_ids]`. Tree lookups are O(children) instead of O(nodes). Built once per file in a single pass.

### Prefilter

Before matching, each file's signature (set of identifiers + node kinds) is checked against rule requirements. Rules that can't possibly match are skipped entirely.

With 20 rules against a typical Python file, **83% of rules are skipped** before the matcher even runs.

### Incremental cache

Content-addressed caching: `hash(file_content + rules_hash) → cached findings`. Unchanged files skip parsing, normalization, and matching entirely.

On repeated scans, this reduces a 2.4s cold scan to a 37ms warm scan.

### Arena allocation

The parse-normalize-match hot path uses arena allocators. Memory is allocated in bulk, reset per file. No individual frees, no fragmentation, no GC pauses.

Arena allocation is **1.58x faster** than the system page allocator for ZIR construction.
