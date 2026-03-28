---
layout: default
title: Quick Start
nav_order: 2
---

# Quick Start

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

Grab the latest from [Releases](https://github.com/copyleftdev/zentinel/releases/latest):

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `zent-linux-x86_64.tar.gz` |
| Linux ARM64 | `zent-linux-aarch64.tar.gz` |
| macOS x86_64 | `zent-macos-x86_64.tar.gz` |
| macOS ARM64 | `zent-macos-aarch64.tar.gz` |

### From source

Requires [Zig 0.14](https://ziglang.org/download/) and `libtree-sitter-dev`.

```bash
git clone https://github.com/copyleftdev/zentinel.git
cd zentinel
zig build -Doptimize=ReleaseFast
# Binary at zig-out/bin/zent (7MB, zero dependencies)
```

## Your first scan

Zentinel ships with built-in rule sets. Point them at your code.

```bash
# Scan with one rule file
zent scan src/**/*.py --config rules/python-security.yaml

# Scan with multiple rule files
zent scan src/ -c rules/go-security.yaml -c rules/community/go-community.yaml

# Scan with ALL rules (loads entire directory)
zent scan src/ --config rules/
```

## Reading the output

```
src/api/auth.py:42:5: eval() can execute arbitrary code [ERROR] (dangerous-eval)
│                │  │  │                                  │       └─ rule ID
│                │  │  │                                  └─ severity
│                │  │  └─ message
│                │  └─ column
│                └─ line
└─ file
```

Exit code `0` means clean. Exit code `1` means findings.

## SARIF output

For CI/CD integration (GitHub Code Scanning, VS Code, etc.):

```bash
zent scan src/ --config rules/python-security.yaml --format sarif > results.sarif
```

Upload to GitHub Code Scanning:

```yaml
# .github/workflows/scan.yml
- name: Run Zentinel
  run: zent scan src/ --config rules/python-security.yaml --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Incremental caching

Zentinel automatically caches results. Files that haven't changed since the last scan are skipped entirely.

```
Scanned 429 file(s) in 37ms — 80 finding(s) (429 cached)
```

The cache lives in `.zentinel-cache/` and invalidates when files or rules change. Add it to your `.gitignore`.
