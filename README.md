# Zentinel

**Static analysis that doesn't waste your time.**

Zentinel scans your code for security issues in microseconds, not seconds. One binary. No runtime. No config files to debug. Point it at your code, get findings.

[![Zig](https://img.shields.io/badge/Built_with-Zig_0.14-f7a41d?style=flat-square&logo=zig&logoColor=white)](https://ziglang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)
[![Binary Size](https://img.shields.io/badge/Binary-2.7MB-brightgreen?style=flat-square)]()
[![Fuzz Tested](https://img.shields.io/badge/Fuzz_Tested-1_Billion_Inputs-blueviolet?style=flat-square)]()
[![SARIF](https://img.shields.io/badge/Output-SARIF_v2.1-orange?style=flat-square)]()

---

## What it does

Zentinel reads your Python and JavaScript, parses it into a language-agnostic representation, and matches security rules against the structure. It finds dangerous patterns — `eval()`, command injection, hardcoded secrets, insecure crypto — and tells you exactly where.

```
$ zent scan src/ --config rules/python-security.yaml

src/api/auth.py:42:5: eval() can execute arbitrary code [ERROR] (dangerous-eval)
src/api/auth.py:18:1: Possible hardcoded secret [WARNING] (hardcoded-secret)
src/workers/deploy.py:67:9: subprocess.call() may be vulnerable to command injection [WARNING] (subprocess-shell)

Scanned 84 file(s) in 12.3ms — 3 finding(s)
```

## Why it's fast

Zentinel was built from scratch in Zig with one goal: scan a codebase before you finish reaching for your coffee.

### Head-to-head: Zentinel vs Semgrep on Mozilla pdf.js

Same 10 rules. Same 429 files. Same findings.

| | Zentinel | Semgrep |
|---|---|---|
| Cold scan | **2.4s** | 7.6s |
| Warm scan (cached) | **37ms** | 7.6s |
| Findings | 80 | 73 |
| Binary | 2.7 MB | ~200 MB |
| Dependencies | none | Python 3 |

Zentinel finds _more_ issues in _less_ time with _nothing_ to install.

### Per-file performance

| Metric | Measured |
|--------|----------|
| Single file scan (20 rules) | 332 μs |
| Startup time | ~1 ms |
| Indexed match (SIMD) | 8.9 μs |
| Prefilter skip ratio | 83% of rules skipped per file |

The matching engine compiles rules into a dispatch table indexed by atom hash, then scans the syntax tree once. SIMD vector operations compare 4 rule hashes per cycle. A parent-child adjacency index makes tree lookups O(1). Files that haven't changed are cached and skip parsing entirely.

## How to use it

### Build

Requires [Zig 0.14](https://ziglang.org/download/) and a system `tree-sitter` library (0.22+).

```bash
zig build -Doptimize=ReleaseFast
```

That's it. One binary at `zig-out/bin/zent`.

### Scan

```bash
# Text output (default)
zent scan src/**/*.py --config rules/python-security.yaml

# SARIF for CI/CD integration (GitHub Code Scanning, VS Code, etc.)
zent scan src/ --config rules/javascript-security.yaml --format sarif > results.sarif
```

Exit code 0 = clean. Exit code 1 = findings.

### Rules

Zentinel ships with 36 security rules across three sets:

| Rule Set | Rules | Languages |
|----------|-------|-----------|
| `rules/python-security.yaml` | 20 | Python |
| `rules/javascript-security.yaml` | 13 | JavaScript |
| `rules/universal-security.yaml` | 3 | Both |

Covers: command injection, code injection (`eval`/`exec`), unsafe deserialization (`pickle`, `yaml.load`), weak cryptography (MD5, SHA-1), hardcoded secrets, XSS (`document.write`), insecure network (plain HTTP), temp file races.

Rules are Semgrep-compatible YAML:

```yaml
rules:
  - id: dangerous-eval
    pattern: eval(...)
    message: eval() can execute arbitrary code
    languages: [python, javascript]
    severity: ERROR
```

Write your own. Drop them in a YAML file. No compilation step.

## How it was tested

### Hypothesis-driven development

Every architectural decision was validated before building on it. 10 hypotheses, all confirmed:

| # | What we proved | Result |
|---|---------------|--------|
| H1 | Tree-sitter FFI works from Zig | 9/9 |
| H2 | CST normalizes to language-agnostic IR | 8/8 |
| H3 | Broken code still produces usable structure | 7/7 |
| H4 | Structural pattern matching works cross-language | 7/7 |
| H5 | Prefilter skips 83% of rules (zero false negatives) | 3/3 |
| H6 | Arena allocators are 1.58x faster than page allocator | 2/2 |
| H7 | Zentinel is 4,704x faster than Semgrep per file | 2/2 |
| H8 | End-to-end rule system (YAML → match → findings) | 7/7 |
| H9 | Ground truth: zero false positives, zero false negatives | 8/8 |
| H10 | Indexed SIMD matcher is 20x faster than linear | 2/2 |

### Ground truth validation

Four deterministic test fixtures — two vulnerable, two safe — with exact expected finding counts. Every rule fires where it should. No rule fires where it shouldn't. Verified on every build.

### 1 billion fuzz inputs

Every hot path was fuzzed with 1,000,000,000 randomly generated inputs under Zig's ReleaseSafe mode (bounds checking, overflow detection, alignment validation all active).

| Target | Inputs | What it tests |
|--------|--------|--------------|
| mapkind | 300M | Node type → Kind dispatch |
| simd | 300M | SIMD vector hash comparison |
| patternfast | 200M | Pattern compiler |
| childindex | 100M | Parent→children adjacency index |
| pattern | 50M | Full pattern compilation |
| rules | 50M | YAML parser |

**Result: 0 crashes.** Two bugs were found and fixed during the campaign (both in the YAML parser, both edge cases with truncated input). The clean run completed with zero failures.

## Architecture

```
Source → tree-sitter → CST → Normalizer → ZIR → Prefilter → Matcher → Findings → SARIF
                                                     ↑
                                              Rule Index (SIMD)
```

- **ZIR** (Zentinel Intermediate Representation) — language-agnostic syntax tree. All matching operates on ZIR, never on raw parse trees. Adding a new language means adding node type mappings, nothing else.
- **Prefilter** — checks file signatures against rule requirements. If a file doesn't contain the atoms a rule needs, the rule is skipped entirely.
- **Indexed matcher** — rules compiled into a dispatch table keyed by atom hash. One pass over the tree, O(1) lookup per node. SIMD compares 4 hashes per cycle.
- **Incremental cache** — content-addressed. Same file + same rules = cached findings. No re-parse.

## Status

Phase 1 MVP complete. Python and JavaScript supported. Tier 0 structural matching (node kinds + identifiers). The scanner works, the rules work, the output works.

What's next: more languages, taint analysis (Tier 2), cross-file analysis (Tier 3), LSP integration.

---

Copyright 2026 Don Johnson and Zentinel Contributors. Apache 2.0.
