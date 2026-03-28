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
| Binary | 7 MB (with web dashboard) | ~200 MB |
| Dependencies | none | Python 3 |
| Install | download one file | pip install + config |
| Rules | 422 | varies |

Same findings. Fraction of the time. Zero dependencies.

## Quick taste

```bash
# CLI scan
zent scan src/ --config rules/python-security.yaml

# Web dashboard
zent serve --port 8000
```

```
src/auth.py:42:5: eval() can execute arbitrary code [ERROR]
src/auth.py:18:1: Possible hardcoded secret [WARNING]
src/deploy.py:67:9: subprocess.call() with shell=True [ERROR]

Scanned 84 file(s) in 12.3ms — 3 finding(s)
```

## 422 Security Rules

68 hand-written + 354 translated from Semgrep's community corpus.

| Category | What it catches |
|----------|----------------|
| Command Injection | `exec()`, `os.system()`, `subprocess.call(..., shell=True)` |
| Code Injection | `eval()`, `eval(f"...")`, `Function()`, `setTimeout(string)` |
| SQL Injection | Tainted data flowing to `cursor.execute()` via custom sources |
| Cryptography | `md5.Sum()`, `hashlib.new("sha1")`, `crypto.createHash("md5")` |
| Secrets | Hardcoded API keys, passwords, tokens |
| Deserialization | `pickle.load()`, `yaml.load()`, `marshal.loads()` |
| XSS | `document.write()`, innerHTML |
| AI / LLM | Hardcoded API keys for OpenAI, Anthropic, Mistral, Cohere |

Custom taint sources in YAML:

```yaml
- id: sql-injection
  pattern: cursor.execute(...)
  sources: [request.args.get(...), input(...)]
  tier: 2
```

## Four Analysis Tiers

- **Tier 0** — Structural matching: node kinds + identifiers
- **Tier 1** — Local reasoning: literal types, argument values, f-string detection
- **Tier 2** — Taint tracking: parameter → variable → sink within functions
- **Tier 3** — Cross-file: tainted data tracked across `import` boundaries

## Web Dashboard

`zent serve` starts a built-in web scanner. Paste a GitHub URL, get:

- Risk score with OWASP Top 10 mapping
- Attack surface radar across 10 security categories
- Riskiest files hotspot chart
- Filterable findings with severity, category, and drill-downs

No Python, no Node, no Docker. Everything embedded in the 7MB binary.

## How it was tested

- **18 hypothesis tests** validating every architectural decision
- Ground truth fixtures with zero false positives, zero false negatives
- **1.2 billion fuzz inputs** across 8 targets — 0 crashes
- Columnar ZIR cache: 57x warm scan speedup
- Rule coverage validation: every hand-written rule has a test
