---
layout: default
title: Home
nav_order: 1
---

<p align="center">
  <img src="logo.png" alt="Zentinel" width="200">
</p>

<h1 align="center">Zentinel</h1>

<p align="center"><strong>Static analysis that doesn't waste your time.</strong></p>

Zentinel scans Python, JavaScript, Go, and TypeScript for security issues in microseconds. One binary, no runtime, no config to debug.

[Get Started](quickstart){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Download](https://github.com/copyleftdev/zentinel/releases){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Why Zentinel?

| | Zentinel | Semgrep |
|---|---|---|
| Scan 429 files | **2.4s** cold / **37ms** cached | 7.6s |
| Binary | 2.7 MB | ~200 MB |
| Dependencies | none | Python 3 |
| Install | download one file | pip install + config |

Same rules. Same findings. Fraction of the time.

## Quick taste

```bash
zent scan src/ --config rules/python-security.yaml
```

```
src/auth.py:42:5: eval() can execute arbitrary code [ERROR]
src/auth.py:18:1: Possible hardcoded secret [WARNING]
src/deploy.py:67:9: subprocess.call() may be vulnerable [WARNING]

Scanned 84 file(s) in 12.3ms — 3 finding(s)
```

## What it detects

64 built-in security rules across four languages, with four analysis tiers:

- **Tier 0** — Structural: `exec()`, `eval()`, `os.system()`, hardcoded secrets
- **Tier 1** — Precision: `subprocess.call(..., shell=True)`, `hashlib.new("md5")`, `eval(f"...")`
- **Tier 2** — Taint: parameter → variable → sink data flow within functions
- **Tier 3** — Cross-file: tainted data tracked across `import` boundaries

Covers: command injection, code injection, unsafe deserialization, weak cryptography, hardcoded secrets, XSS, insecure network, SQL injection patterns.

All rules are Semgrep-compatible YAML. Write your own in seconds.

## How it was tested

- 16 hypothesis tests validating every architectural decision
- Ground truth fixtures with zero false positives, zero false negatives
- **1 billion fuzz inputs** across all hot paths — 0 crashes
