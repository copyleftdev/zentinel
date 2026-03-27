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
| `--config <path>` | `-c` | Rules file (required) |
| `--format <text\|sarif>` | `-f` | Output format (default: `text`) |

**Examples:**

```bash
# Single file
zent scan app.py -c rules/python-security.yaml

# Multiple files
zent scan src/auth.py src/api.py -c rules/python-security.yaml

# Glob pattern
zent scan src/**/*.js -c rules/javascript-security.yaml

# SARIF output
zent scan src/ -c rules/python-security.yaml -f sarif > results.sarif
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Findings detected |

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

### SARIF

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "zentinel" } },
    "results": [...]
  }]
}
```

SARIF v2.1.0 with full location data. Compatible with:
- GitHub Code Scanning
- VS Code SARIF Viewer
- Azure DevOps
- Any SARIF-consuming tool

## Caching

Zentinel caches scan results in `.zentinel-cache/`. The cache key is derived from:
- File content hash
- Rules file hash

If neither changes, the file is served from cache. This makes repeated scans near-instant.

To clear the cache:

```bash
rm -rf .zentinel-cache/
```
