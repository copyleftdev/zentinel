# Changelog

## v0.3.0 — 2026-03-27

Community rule corpus and Tier 3 cross-file analysis.

### Community Rules (354 rules)
- Translated from Semgrep's public rule repository (github.com/semgrep/semgrep-rules)
- Python: 271 rules, Go: 50, TypeScript: 33, JavaScript: 31
- Covers: AI/LLM API key leaks, SQL injection, XSS, SSRF, path traversal, crypto misuse, and more
- Translation script at `scripts/translate_semgrep_rules.py` for re-running on updates
- Total corpus: 68 hand-written + 354 community = 422 rules

### Tier 3: Cross-File Taint Analysis
- Two-pass scan: collect exports/imports, then analyze cross-file flows
- Tracks tainted data across `from X import Y` boundaries
- One-hop: caller imports function, calls with tainted arg, callee reaches sink
- H16: 5/5 CONFIRMED

### Custom Source/Sink Configuration
- Rules specify `sources:` to define where tainted data enters
- 4 Python taint rules with configurable sources (request, input, sys.argv)
- H17: 6/6 CONFIRMED

---

## v0.2.1 — 2026-03-27

Custom taint sources, fuzz hardening, and polish.

### Custom Source/Sink Configuration
- Rules can now specify `sources:` to define where tainted data enters
- Configurable taint sources: `request.args.get(...)`, `input(...)`, `sys.argv`, etc.
- When sources are specified, taint seeds from matching calls instead of function parameters
- 4 new Python taint rules: sql-injection, exec, eval, os.system with custom sources
- Structural matchers now skip tier>=2 rules (handled exclusively by taint engine)

### Fuzz Campaign (v0.2.1)
- 1.1 billion inputs across 7 targets, 0 crashes
- New target: `taintsource` — 100M inputs fuzzing source pattern parser
- `mapkind` now fuzzes all 4 languages (Python, JS, Go, TypeScript)
- Updated structure injection with Go/TS keywords and taint patterns

### Testing
- H17: Custom taint source/sink configuration (6/6 CONFIRMED)
- 17/17 hypotheses confirmed total

---

## v0.2.0 — 2026-03-27

Tiered analysis engine and multi-language support.

### Tier 1: Local Reasoning
- LiteralKind classification (string/int/float/bool/null/regex/collection) packed into ZIR node flags
- Argument constraints: keyword args (`shell=True`), exact string values (`"md5"`), f-string detection
- Assignment precision: `$KEY = "..."` only fires on string literal RHS (62.5% FP reduction)
- `--max-tier` CLI flag for tier enforcement
- 10 new precision rules (subprocess shell=True, hashlib.new, eval f-string, crypto precise)

### Tier 2: Intra-Procedural Taint
- Per-function taint tracking: parameter → variable → sink data flow
- Assignment propagation, f-string interpolation, call result tainting
- 75μs per function analysis, zero false positives on safe inputs

### Tier 3: Cross-File Taint
- Two-pass scan: collect exports/imports, then analyze cross-file flows
- Tracks tainted data across `from X import Y` boundaries
- One-hop: A→B (caller imports function, calls with tainted arg, callee reaches sink)
- Zero overhead when no Tier 3 rules present

### Languages
- Go support (tree-sitter-go v0.23.4, 45 node mappings, 4 security rules)
- TypeScript support (tree-sitter-typescript v0.23.2, 12 TS-specific + 108 shared mappings, 14 security rules)

### Testing
- 16 hypothesis tests, all confirmed (H11–H16 new)
- 3 new benchmarks (B-10 through B-12), all passing
- Ground truth: 30 Python + 19 JavaScript findings, zero FP/FN

### Rule Corpus
- 64 total rules: 27 Python + 16 JavaScript + 4 Go + 14 TypeScript + 3 universal
- Tier 0 (structural) + Tier 1 (precision) rules across all languages

---

## v0.1.0 — 2026-03-27

Initial release. Phase 1 MVP complete.

### Scanner
- `zent scan` CLI with `--config` and `--format text|sarif`
- Python and JavaScript support via tree-sitter
- Incremental cache (content-addressed, skip unchanged files)
- SARIF v2.1.0 output for CI/CD integration

### Rule engine
- Semgrep-compatible YAML rule format
- Three pattern types: `func(...)`, `obj.method(...)`, `$VAR = "..."`
- Prefilter: 83% of rules skipped per file (zero false negatives)
- Indexed matcher with SIMD hash dispatch (20x faster than linear scan)

### Rule corpus
- 20 Python security rules
- 13 JavaScript security rules
- 3 cross-language rules
- Ground truth validated: zero false positives, zero false negatives

### Performance
- 332 μs per file (20 rules, ReleaseFast)
- 37 ms warm scan on 429-file codebase
- 2.7 MB static binary, no runtime dependencies
- 4,704x faster than Semgrep on equivalent workload

### Testing
- 10 hypothesis tests, all confirmed
- 4 deterministic ground truth fixtures
- 1 billion fuzz inputs across 6 targets, 0 crashes
