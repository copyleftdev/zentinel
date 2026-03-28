<p align="center">
  <img src="media/logo.png" alt="Zentinel" width="200">
</p>

<h1 align="center">Zentinel</h1>

<p align="center"><strong>Static analysis that doesn't waste your time.</strong></p>

Zentinel scans your code for security issues in microseconds, not seconds. One binary. No runtime. No config files to debug. Point it at your code, get findings.

[![Zig](https://img.shields.io/badge/Built_with-Zig_0.14-f7a41d?style=flat-square&logo=zig&logoColor=white)](https://ziglang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)
[![Binary Size](https://img.shields.io/badge/Binary-2.7MB-brightgreen?style=flat-square)]()
[![Fuzz Tested](https://img.shields.io/badge/Fuzz_Tested-1.1_Billion_Inputs-blueviolet?style=flat-square)]()
[![SARIF](https://img.shields.io/badge/Output-SARIF_v2.1-orange?style=flat-square)]()
[![Downloads](https://img.shields.io/github/downloads/copyleftdev/zentinel/total?style=flat-square&label=Downloads&color=brightgreen)](https://github.com/copyleftdev/zentinel/releases)
[![Release](https://img.shields.io/github/v/release/copyleftdev/zentinel?style=flat-square&label=Release)](https://github.com/copyleftdev/zentinel/releases/latest)

---

## What it does

Zentinel reads your Python, JavaScript, Go, and TypeScript, parses it into a language-agnostic representation, and matches security rules against the structure. It finds dangerous patterns — `eval()`, command injection, hardcoded secrets, insecure crypto, tainted data flows — and tells you exactly where.

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

## Install

### Quick install (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/copyleftdev/zentinel/main/install.sh | sh
```

### Homebrew (macOS)

```bash
brew install copyleftdev/tap/zentinel
```

### Download binary

Grab the latest release for your platform from [GitHub Releases](https://github.com/copyleftdev/zentinel/releases/latest).

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `zent-linux-x86_64.tar.gz` |
| Linux ARM64 | `zent-linux-aarch64.tar.gz` |
| macOS x86_64 | `zent-macos-x86_64.tar.gz` |
| macOS ARM64 | `zent-macos-aarch64.tar.gz` |

### Build from source

Requires [Zig 0.14](https://ziglang.org/download/) and a system `tree-sitter` library (0.22+).

```bash
zig build -Doptimize=ReleaseFast
```

One binary at `zig-out/bin/zent` (7MB, zero dependencies).

### Scan

```bash
# Text output (default)
zent scan src/**/*.py --config rules/python-security.yaml

# Agent/JSON output — structured for AI agents and automation
zent scan src/ --config rules.yaml --format agent

# SARIF for CI/CD integration (GitHub Code Scanning, VS Code, etc.)
zent scan src/ --config rules.yaml --format sarif > results.sarif

# Web dashboard — paste a GitHub URL, get a security report
zent serve --port 8000
```

Exit code 0 = clean. Exit code 1 = findings.

### Agent mode

`--format agent` outputs structured JSON designed for AI agent consumption. Each finding includes category tags, confidence scores, fix suggestions, and source context — everything an agent needs to triage and patch without reading files separately.

```json
{
  "findings": [{
    "file": "src/auth.py",
    "line": 42, "col": 5,
    "severity": "ERROR", "severity_num": 3,
    "category": "command-injection",
    "confidence": 0.90,
    "message": "exec.Command() can lead to command injection",
    "fix": "Validate and sanitize all arguments to exec.Command().",
    "context": {
      "lines": [
        {"num": 41, "text": "func run(cmd string) {", "highlight": false},
        {"num": 42, "text": "    exec.Command(cmd)", "highlight": true},
        {"num": 43, "text": "}", "highlight": false}
      ]
    }
  }]
}
```

Categories: `command-injection`, `code-injection`, `sql-injection`, `weak-cryptography`, `hardcoded-secret`, `unsafe-deserialization`, `xss`, `insecure-network`, `tainted-data-flow`

### Rules

Zentinel ships with 422 security rules — 68 hand-written + 354 translated from Semgrep's community corpus:

| Rule Set | Rules | Languages |
|----------|-------|-----------|
| `rules/python-security.yaml` | 31 | Python |
| `rules/javascript-security.yaml` | 16 | JavaScript |
| `rules/typescript-security.yaml` | 14 | TypeScript |
| `rules/go-security.yaml` | 4 | Go |
| `rules/universal-security.yaml` | 3 | All |
| `rules/community/python-community.yaml` | 271 | Python |
| `rules/community/go-community.yaml` | 50 | Go |
| `rules/community/typescript-community.yaml` | 33 | TypeScript |
| `rules/community/javascript-community.yaml` | 31 | JavaScript |

Covers: command injection, code injection (`eval`/`exec`), unsafe deserialization (`pickle`, `yaml.load`), weak cryptography (MD5, SHA-1), hardcoded secrets, XSS (`document.write`), insecure network (plain HTTP), temp file races, SQL injection via tainted data flow.

Rules are Semgrep-compatible YAML. Tier 2 rules support custom taint sources:

```yaml
rules:
  - id: sql-injection
    pattern: cursor.execute(...)
    sources: [request.args.get(...), input(...)]
    message: SQL injection — user input flows to database query
    languages: [python]
    severity: ERROR
    tier: 2
```

Write your own. Drop them in a YAML file. No compilation step.

## How it was tested

### Hypothesis-driven development

Every architectural decision was validated before building on it. 17 hypotheses, all confirmed:

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
| H11 | Literal classification across Python + JS | 13/13 |
| H12 | Assignment precision (62.5% FP reduction) | 8/8 |
| H13 | Argument constraints (keyword, value, f-string) | 6/6 |
| H14 | Tier enforcement + cost boundaries | 5/5 |
| H15 | Intra-procedural taint tracking | 8/8 |
| H16 | Cross-file taint tracking | 5/5 |
| H17 | Custom taint source/sink configuration | 6/6 |
| H18 | Columnar ZIR storage (57x warm speedup) | 5/5 |

### Ground truth validation

Eight deterministic test fixtures across four languages — vulnerable and safe variants — with exact expected finding counts. Every rule fires where it should. No rule fires where it shouldn't. Verified on every build.

### 1.2 billion fuzz inputs

Every hot path was fuzzed with 1,200,000,000 randomly generated inputs under Zig's ReleaseSafe mode (bounds checking, overflow detection, alignment validation all active).

| Target | Inputs | What it tests |
|--------|--------|--------------|
| mapkind | 300M | Node type → Kind dispatch (4 languages) |
| simd | 300M | SIMD vector hash comparison |
| patternfast | 200M | Pattern compiler |
| childindex | 100M | Parent→children adjacency index |
| taintsource | 100M | Taint source pattern parser |
| columnar | 100M | Columnar ZIR deserializer |
| pattern | 50M | Full pattern compilation |
| rules | 50M | YAML parser |

**Result: 0 crashes.** Three campaigns run (v0.1.0, v0.2.1, v0.4.0). Clean run on current codebase with zero failures.

## Architecture

```
Source → tree-sitter → CST → Normalizer → ZIR → Prefilter → Matcher → Findings → SARIF
                                                     ↑              ↑
                                              Rule Index (SIMD)   Taint Engine
                                                                    ↑
                                                              Cross-File Index
```

## Status

Four languages. Four analysis tiers. 422 security rules. 18 hypotheses confirmed. 1.2 billion fuzz inputs.

- **Tier 0** — Structural matching (node kinds + identifiers)
- **Tier 1** — Local reasoning (literal classification, argument constraints, f-string detection)
- **Tier 2** — Intra-procedural taint tracking (parameter → variable → sink, configurable sources)
- **Tier 3** — Cross-file taint tracking (import → call → sink across module boundaries)

What's next: more languages, deeper taint propagation (multi-hop cross-file), framework-aware sources.

---

Copyright 2026 Don Johnson and Zentinel Contributors. Apache 2.0.
