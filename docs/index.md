---
layout: default
title: Home
nav_order: 1
---

# Zentinel

**Static analysis that doesn't waste your time.**

Zentinel scans Python and JavaScript for security issues in microseconds. One binary, no runtime, no config to debug.

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

36 built-in security rules covering:

- Command injection (`exec`, `eval`, `os.system`, `subprocess`)
- Unsafe deserialization (`pickle`, `yaml.load`, `marshal`)
- Weak cryptography (MD5, SHA-1)
- Hardcoded secrets
- XSS patterns (`document.write`)
- Insecure network (plain HTTP)

All rules are Semgrep-compatible YAML. Write your own in seconds.

## How it was tested

- 10 hypothesis tests validating every architectural decision
- Ground truth fixtures with zero false positives, zero false negatives
- **1 billion fuzz inputs** across all hot paths — 0 crashes
