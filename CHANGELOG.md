# Changelog

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
