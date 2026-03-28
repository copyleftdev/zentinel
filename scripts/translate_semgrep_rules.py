#!/usr/bin/env python3
"""Translate Semgrep community rules into Zentinel format.

Reads the semgrep-rules repository and extracts rules that Zentinel can handle:
- Simple `pattern:` rules → direct translation
- `pattern-either:` rules → explode each alternative into a separate Zentinel rule
- `patterns:` with simple pattern entries → extract the pattern

Filters to languages Zentinel supports: python, javascript, typescript, go.

Usage:
    python3 scripts/translate_semgrep_rules.py /path/to/semgrep-rules ./rules/community/
"""

import yaml
import os
import sys
import re
from pathlib import Path
from collections import defaultdict

SUPPORTED_LANGS = {'python', 'javascript', 'typescript', 'go'}

# Patterns Zentinel can compile: func(...), obj.method(...), $VAR = "..."
# Also Tier 1: func(arg), obj.method(..., key=val)
CALL_RE = re.compile(r'^[a-zA-Z_][\w]*\s*\(')
MEMBER_CALL_RE = re.compile(r'^[a-zA-Z_][\w]*\.[a-zA-Z_][\w.]*\s*\(')
ASSIGN_RE = re.compile(r'^\$?\w+\s*=\s*')


def can_translate(pattern: str) -> bool:
    """Check if a Semgrep pattern is translatable to Zentinel."""
    p = pattern.strip()
    if not p:
        return False
    # Must be a call, member call, or assignment pattern
    if CALL_RE.match(p) or MEMBER_CALL_RE.match(p) or ASSIGN_RE.match(p):
        return True
    return False


def extract_patterns(rule: dict) -> list[str]:
    """Extract all translatable patterns from a Semgrep rule."""
    patterns = []

    # Simple pattern
    if 'pattern' in rule and isinstance(rule['pattern'], str):
        p = rule['pattern'].strip()
        if can_translate(p):
            patterns.append(p)

    # pattern-either: list of alternatives
    if 'pattern-either' in rule:
        for item in rule['pattern-either']:
            if isinstance(item, dict) and 'pattern' in item:
                p = item['pattern'].strip()
                if can_translate(p):
                    patterns.append(p)

    # patterns: list (often has pattern + pattern-not combos)
    if 'patterns' in rule:
        for item in rule['patterns']:
            if isinstance(item, dict) and 'pattern' in item:
                p = item['pattern'].strip()
                if can_translate(p):
                    patterns.append(p)

    return patterns


def translate_severity(sev: str) -> str:
    """Map Semgrep severity to Zentinel severity."""
    sev = sev.upper()
    if sev in ('ERROR', 'CRITICAL', 'HIGH'):
        return 'ERROR'
    if sev in ('WARNING', 'MEDIUM'):
        return 'WARNING'
    return 'INFO'


def translate_rule(rule: dict, source_file: str) -> list[dict]:
    """Translate a single Semgrep rule into one or more Zentinel rules."""
    rule_id = rule.get('id', '')
    message = rule.get('message', '').strip()
    severity = translate_severity(rule.get('severity', 'WARNING'))
    languages = rule.get('languages', [])

    # Filter to supported languages
    supported = [l for l in languages if l in SUPPORTED_LANGS]
    if not supported:
        return []

    patterns = extract_patterns(rule)
    if not patterns:
        return []

    # Truncate message to one line
    message = message.split('\n')[0][:200]

    results = []
    for i, pattern in enumerate(patterns):
        rid = rule_id if len(patterns) == 1 else f"{rule_id}-{i+1}"
        # Prefix with zentinel namespace
        if not rid.startswith('zentinel.'):
            rid = f"community.{rid}"

        results.append({
            'id': rid,
            'pattern': pattern,
            'message': message,
            'languages': supported,
            'severity': severity,
        })

    return results


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <semgrep-rules-dir> <output-dir>")
        sys.exit(1)

    rules_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)

    # Collect all translated rules by language
    by_lang = defaultdict(list)
    seen_ids = set()
    total_files = 0
    total_semgrep = 0
    total_translated = 0
    skipped_dup = 0

    for yf in sorted(rules_dir.rglob('*.yaml')):
        try:
            with open(yf) as f:
                data = yaml.safe_load(f)
            if not data or 'rules' not in data:
                continue
            total_files += 1
            for r in data['rules']:
                total_semgrep += 1
                translated = translate_rule(r, str(yf.relative_to(rules_dir)))
                for t in translated:
                    # Deduplicate by pattern + languages
                    dedup_key = (t['pattern'], tuple(sorted(t['languages'])))
                    if dedup_key in seen_ids:
                        skipped_dup += 1
                        continue
                    seen_ids.add(dedup_key)
                    total_translated += 1
                    for lang in t['languages']:
                        by_lang[lang].append(t)
        except Exception as e:
            pass

    # Write per-language YAML files
    for lang, rules in sorted(by_lang.items()):
        outfile = output_dir / f"{lang}-community.yaml"
        output = {'rules': []}
        for r in rules:
            entry = {
                'id': r['id'],
                'pattern': r['pattern'],
                'message': r['message'],
                'languages': r['languages'],
                'severity': r['severity'],
            }
            output['rules'].append(entry)

        # Write YAML manually to avoid anchors/aliases
        with open(outfile, 'w') as f:
            f.write("rules:\n")
            for r in output['rules']:
                f.write(f"  - id: {r['id']}\n")
                f.write(f"    pattern: {r['pattern']}\n")
                # Escape message for YAML
                msg = r['message'].replace('"', '\\"')
                f.write(f'    message: "{msg}"\n')
                langs = ', '.join(r['languages'])
                f.write(f"    languages: [{langs}]\n")
                f.write(f"    severity: {r['severity']}\n")
                f.write(f"\n")

        print(f"  {lang}: {len(rules)} rules → {outfile}")

    print(f"\n  Summary:")
    print(f"    Semgrep files scanned: {total_files}")
    print(f"    Semgrep rules found:   {total_semgrep}")
    print(f"    Translated to Zentinel: {total_translated}")
    print(f"    Duplicates skipped:    {skipped_dup}")
    print(f"    Languages:             {', '.join(sorted(by_lang.keys()))}")


if __name__ == '__main__':
    main()
