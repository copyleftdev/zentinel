---
layout: default
title: Quick Start
nav_order: 2
---

# Quick Start

## Install

### From release (recommended)

Download the latest binary for your platform from [Releases](https://github.com/copyleftdev/zentinel/releases).

```bash
# Linux x86_64
curl -LO https://github.com/copyleftdev/zentinel/releases/latest/download/zent-linux-x86_64.tar.gz
tar xzf zent-linux-x86_64.tar.gz
chmod +x zent-linux-x86_64
sudo mv zent-linux-x86_64 /usr/local/bin/zent

# macOS Apple Silicon
curl -LO https://github.com/copyleftdev/zentinel/releases/latest/download/zent-macos-aarch64.tar.gz
tar xzf zent-macos-aarch64.tar.gz
chmod +x zent-macos-aarch64
sudo mv zent-macos-aarch64 /usr/local/bin/zent
```

### From source

Requires [Zig 0.14](https://ziglang.org/download/) and `libtree-sitter-dev`.

```bash
git clone https://github.com/copyleftdev/zentinel.git
cd zentinel
zig build -Doptimize=ReleaseFast
# Binary at zig-out/bin/zent
```

## Your first scan

Zentinel ships with built-in rule sets. Grab one and point it at your code.

```bash
# Scan Python files
zent scan src/**/*.py --config rules/python-security.yaml

# Scan JavaScript files
zent scan src/**/*.js --config rules/javascript-security.yaml

# Scan both
zent scan src/ --config rules/universal-security.yaml
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
