---
layout: default
title: CLI Reference
nav_order: 3
---

# CLI Reference

## Usage

```
zent <command> [options]
```

## Commands

### `scan`

Scan files for security issues.

```
zent scan <files...> [options]
```

**Options:**

| Flag | Short | Description |
|------|-------|-------------|
| `--config <path>` | `-c` | Rules file or directory (repeatable) |
| `--format <format>` | `-f` | Output format: `text`, `sarif`, `agent` (default: `text`) |
| `--max-tier <0-3>` | | Maximum rule tier to run (default: all) |

**Examples:**

```bash
# Single file
zent scan app.py -c rules/python-security.yaml

# Multiple files
zent scan src/auth.py src/api.py -c rules/python-security.yaml

# Multiple rule files
zent scan src/ -c rules/go-security.yaml -c rules/community/go-community.yaml

# Load all rules from a directory (recursive)
zent scan src/ --config rules/

# SARIF output
zent scan src/ -c rules/python-security.yaml -f sarif > results.sarif

# Agent/JSON output (for AI agents and automation)
zent scan src/ -c rules/python-security.yaml -f agent

# Tier 0 only (structural matching, fastest)
zent scan src/ -c rules.yaml --max-tier 0
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Findings detected |

### `serve`

Start the web scanner dashboard.

```
zent serve [options]
```

| Flag | Short | Description |
|------|-------|-------------|
| `--port <port>` | `-p` | HTTP port (default: 8000) |
| `--rules <path>` | `-r` | Rules directory (default: `rules`) |

### `help`

```
zent help
```

## Output formats

### Text (default)

```
file:line:col: message [SEVERITY] (rule-id)
```

Human-readable, one finding per line. Grep-friendly.

### Agent / JSON

```bash
zent scan src/ -c rules.yaml --format agent
```

Structured JSON designed for AI agent consumption. Each finding includes:

| Field | Type | Description |
|-------|------|-------------|
| `file` | string | File path |
| `line`, `col` | int | Start position (1-based) |
| `end_line`, `end_col` | int | End position |
| `severity` | string | `ERROR`, `WARNING`, or `INFO` |
| `severity_num` | int | 3, 2, or 1 (for sorting) |
| `rule_id` | string | Rule identifier |
| `category` | string | Machine-readable tag (see below) |
| `confidence` | float | 0.0-1.0 confidence score |
| `message` | string | Human-readable description |
| `fix` | string | Actionable remediation suggestion |
| `context.lines[]` | array | Source lines with `num`, `text`, `highlight` |

**Categories:**

| Tag | Description |
|-----|-------------|
| `command-injection` | Shell command execution |
| `code-injection` | eval/exec/Function/setTimeout |
| `sql-injection` | Database query injection |
| `weak-cryptography` | MD5, SHA-1 |
| `hardcoded-secret` | API keys, passwords, tokens |
| `unsafe-deserialization` | pickle, yaml.load, marshal |
| `xss` | Cross-site scripting |
| `insecure-network` | Plain HTTP, disabled TLS |
| `tainted-data-flow` | Taint tracking findings |

**Confidence scoring:**

- 0.90+ — High confidence (ERROR severity, Tier 1+ precision)
- 0.70-0.89 — Medium confidence (WARNING, standard rules)
- 0.40-0.69 — Low confidence (INFO, community rules)

### SARIF

```bash
zent scan src/ -c rules.yaml --format sarif > results.sarif
```

SARIF v2.1.0 with full location data. Compatible with GitHub Code Scanning, VS Code SARIF Viewer, Azure DevOps.

## Caching

Zentinel has two cache layers:

1. **ZIR cache** — Columnar binary format of parsed/normalized syntax trees. Content-addressed by source hash + normalizer version. Survives rule changes. 57x faster than re-parsing.

2. **Findings cache** — Cached scan results. Content-addressed by source hash + rules hash. When both source and rules are unchanged, findings are served instantly.

Cache lives in `.zentinel-cache/`. To clear:

```bash
rm -rf .zentinel-cache/
```

## Analysis Tiers

| Tier | Analysis | Cost | Use `--max-tier` to limit |
|------|----------|------|--------------------------|
| 0 | Structural matching (node kinds + identifiers) | O(nodes) | `--max-tier 0` |
| 1 | Local reasoning (literal types, argument values) | O(nodes x depth) | `--max-tier 1` |
| 2 | Taint tracking (parameter → variable → sink) | O(nodes^2/function) | `--max-tier 2` |
| 3 | Cross-file taint (import → call → sink) | O(files x nodes) | default |
