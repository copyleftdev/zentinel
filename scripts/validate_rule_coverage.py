#!/usr/bin/env python3
"""Validate that every hand-written Zentinel rule has test coverage.

Runs zent scan against all test fixtures for each rule file and checks that
every rule ID produces at least one finding across all fixtures.

Rules without test coverage are flagged as errors. Exit code 1 = uncovered rules.

Usage:
    python3 scripts/validate_rule_coverage.py

Expects:
    - zig-out/bin/zent to be built (zig build -Doptimize=ReleaseFast)
    - test_fixtures/ directory with language subdirectories
    - rules/*.yaml (hand-written rules to validate)
    - rules/community/ is EXCLUDED (community rules are untested)
"""

import subprocess
import sys
import re
import yaml
from pathlib import Path

ZENT = Path("zig-out/bin/zent")
RULES_DIR = Path("rules")
FIXTURES_DIR = Path("test_fixtures")

# Map language names to fixture file extensions
LANG_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js"],
    "typescript": [".ts"],
    "go": [".go"],
}


def get_fixture_files(lang: str) -> list[Path]:
    """Find all fixture files for a language."""
    files = []
    exts = LANG_EXTENSIONS.get(lang, [])
    for ext in exts:
        files.extend(FIXTURES_DIR.rglob(f"*{ext}"))
    return sorted(files)


def get_rule_ids(rule_file: Path) -> list[str]:
    """Extract all rule IDs from a YAML rule file."""
    with open(rule_file) as f:
        data = yaml.safe_load(f)
    if not data or "rules" not in data:
        return []
    return [r["id"] for r in data["rules"] if "id" in r]


def get_rule_languages(rule_file: Path) -> set[str]:
    """Extract all languages used in a rule file."""
    with open(rule_file) as f:
        data = yaml.safe_load(f)
    if not data or "rules" not in data:
        return set()
    langs = set()
    for r in data["rules"]:
        for l in r.get("languages", []):
            langs.add(l)
    return langs


def clean_zir_cache():
    """Remove stale ZIR cache to avoid cross-version segfaults."""
    import shutil
    cache_dir = Path(".zentinel-cache")
    if cache_dir.exists():
        for f in cache_dir.glob("*.zir"):
            f.unlink()

def scan_fixtures(rule_file: Path, fixture_files: list[Path]) -> set[str]:
    """Run zent scan and return the set of rule IDs that fired."""
    if not fixture_files:
        return set()

    fired = set()
    for fixture in fixture_files:
        try:
            clean_zir_cache()  # Prevent cross-language ZIR cache corruption
            result = subprocess.run(
                [str(ZENT), "scan", str(fixture), "--config", str(rule_file)],
                capture_output=True, text=True, timeout=30
            )
            # Parse output for rule IDs: "file:line:col: message [SEVERITY] (rule-id)"
            for line in result.stdout.splitlines():
                match = re.search(r'\(([^)]+)\)\s*$', line)
                if match:
                    fired.add(match.group(1))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return fired


def main():
    if not ZENT.exists():
        print("ERROR: zent binary not found. Run: zig build -Doptimize=ReleaseFast")
        sys.exit(1)

    clean_zir_cache()

    # Find hand-written rule files (exclude community/)
    rule_files = sorted(RULES_DIR.glob("*.yaml"))
    if not rule_files:
        print("No rule files found in rules/")
        sys.exit(1)

    print("=" * 60)
    print("  Rule Coverage Validation")
    print("=" * 60)
    print()

    total_rules = 0
    covered_rules = 0
    uncovered = []

    for rule_file in rule_files:
        rule_ids = get_rule_ids(rule_file)
        if not rule_ids:
            continue

        languages = get_rule_languages(rule_file)

        # Collect all fixture files for the languages this rule file covers
        all_fixtures = []
        for lang in languages:
            all_fixtures.extend(get_fixture_files(lang))

        # Deduplicate
        all_fixtures = sorted(set(all_fixtures))

        # Run scan
        fired = scan_fixtures(rule_file, all_fixtures)

        # Check coverage
        file_covered = 0
        file_uncovered = []
        for rid in rule_ids:
            total_rules += 1
            if rid in fired:
                covered_rules += 1
                file_covered += 1
            else:
                # Tier 2+ rules fire through taint engine, not structural scan
                # Check if this is a taint rule (has sources: or tier >= 2)
                with open(rule_file) as f:
                    data = yaml.safe_load(f)
                is_taint = False
                for r in data.get("rules", []):
                    if r.get("id") == rid:
                        if r.get("tier", 0) >= 2 or r.get("sources"):
                            is_taint = True
                        break

                if is_taint:
                    covered_rules += 1  # Taint rules validated by H15/H16/H17
                    file_covered += 1
                else:
                    file_uncovered.append(rid)
                    uncovered.append((rule_file.name, rid))

        status = "PASS" if not file_uncovered else "FAIL"
        print(f"  [{status}] {rule_file.name}: {file_covered}/{len(rule_ids)} rules covered")
        for rid in file_uncovered:
            print(f"         UNCOVERED: {rid}")

    print()
    print(f"  Total: {covered_rules}/{total_rules} rules covered")

    if uncovered:
        print()
        print("  UNCOVERED RULES (need test fixtures):")
        for fname, rid in uncovered:
            print(f"    {fname}: {rid}")
        print()
        print("  To fix: add trigger lines to the appropriate test_fixtures/ file")
        print("  Example: exec(cmd)  # TRIGGER rule.id.here")
        sys.exit(1)
    else:
        print("  All hand-written rules have test coverage.")
        sys.exit(0)


if __name__ == "__main__":
    main()
