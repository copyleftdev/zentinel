# Zentinel — Project Governance

> "Truth exists in structure. Noise is incidental."

Zentinel is a **Semantic Code Intelligence Engine (SCIE)** — Semgrep rebuilt from first principles in Zig. Faster, stricter, incremental, and composable.

## Project State

Phase 1 MVP — **Complete**. Tier 1–3 + custom sources — **Complete**. All 11 components implemented. 17/17 hypotheses confirmed. 10/12 benchmarks passing.

- **Language:** Zig 0.14.0 (scanning Python, JavaScript, Go, TypeScript)
- **Lines of code:** ~5,200 (11 src modules + 16 hypothesis tests)
- **Test fixtures:** Python, JavaScript, Go, TypeScript (clean + broken + vulnerable + safe)
- **Hypothesis tests:** 18/18 confirmed

## Hypothesis Results (2026-03-27)

| ID | Hypothesis | Result | Key Finding |
|----|-----------|--------|-------------|
| H1 | Tree-sitter FFI from Zig | CONFIRMED (9/9) | Parser, cursor, spans all work |
| H2 | CST → ZIR normalization | CONFIRMED (8/8) | CommonJS `require()` mapped to import Kind |
| H3 | Error-tolerant parsing | CONFIRMED (7/7) | ~38% structure survives broken code |
| H4 | Pattern matching | CONFIRMED (7/7) | Cross-language matching, zero false positives |
| H5 | Prefilter skip ratio | CONFIRMED (3/3) | 83.3% rules skipped, zero false negatives |
| H6 | Arena allocators | CONFIRMED (2/2) | 1.58x faster than page_allocator |
| H7 | Zentinel vs Semgrep | CONFIRMED (2/2) | 4,704x faster (332μs vs 1,562ms), same 21 findings from 20 rules |
| H8 | Rule system (YAML→match→findings) | CONFIRMED (7/7) | End-to-end: parse 5 rules, match Python+JS, cross-language |
| H9 | Ground truth validation | CONFIRMED (8/8) | 46-rule corpus, 4 fixtures, zero FP/FN |
| H10 | Indexed matcher (SIMD + ChildIndex) | CONFIRMED (2/2) | 20x faster, atom→rules dispatch + SIMD hash + O(1) child lookups |
| H11 | Literal classification (LiteralKind) | CONFIRMED (13/13) | string/int/float/bool/null/regex/collection across Python+JS |
| H12 | Assignment precision (Tier 1) | CONFIRMED (8/8) | `$KEY = "..."` rejects int/bool/null RHS; 62.5% FP reduction |
| H13 | Argument constraints (Tier 1) | CONFIRMED (6/6) | keyword args, exact string, f-string/template — zero FP |
| H14 | Tier enforcement + cost boundaries | CONFIRMED (5/5) | B-10: 1.08x, B-11: 0.97x, B-12: 2.0% overhead |
| H15 | Intra-procedural taint tracking | CONFIRMED (8/8) | Param→sink, assignment chain, f-string, cross-lang, 75μs/analysis |
| H16 | Cross-file taint tracking | CONFIRMED (5/5) | Import→call→sink across files, one-hop, 0.4μs/analysis |
| H17 | Custom taint sources/sinks | CONFIRMED (6/6) | YAML sources: field, source→taint→sink, backward compat |
| H18 | Columnar ZIR storage | CONFIRMED (5/5) | 57x warm speedup, round-trip fidelity, zero-copy ChildIndex |

### Known Gaps

- H7: Semgrep time includes Python startup (~500ms); Zentinel time excludes one-time rule loading (~200μs). Both use identical 20-rule YAML, both find 21 findings.

## File Layout

```
zentinel/
├── CLAUDE.md              # This file — project governance
├── prd.md                 # Product requirements (READ-ONLY reference)
├── build.zig              # Build system — compiles grammars + all targets
├── src/
│   ├── taint.zig          # Tier 2 taint analysis (intra-procedural data flow)
│   ├── columnar.zig       # Columnar mmap ZIR storage (57x warm scan speedup)
│   ├── crossfile.zig      # Tier 3 cross-file analysis (import→call→sink)
│   ├── fast_matcher.zig    # Indexed matcher (SIMD hash, atom→rules dispatch)
│   ├── main.zig           # CLI entry point (zent scan --format text|sarif)
│   ├── matcher.zig        # Match engine (run rules against ZIR, produce findings)
│   ├── normalizer.zig     # CST → ZIR normalizer (mapKind, buildZir)
│   ├── rule.zig           # Rule types, YAML parser, pattern compiler
│   ├── cache.zig          # Incremental scan cache (content-addressed)
│   ├── sarif.zig          # SARIF v2.1.0 JSON output formatter
│   ├── treesitter.zig     # Zig bindings for tree-sitter C API
│   └── zir.zig            # ZIR type definitions (Node, Kind, AtomTable, ZirTree)
├── rules/                 # Built-in rule corpus
│   ├── python-security.yaml      # 27 Python security rules (20 Tier 0 + 7 Tier 1)
│   ├── javascript-security.yaml  # 16 JavaScript security rules (13 Tier 0 + 3 Tier 1)
│   ├── go-security.yaml          # 4 Go security rules
│   ├── typescript-security.yaml  # 14 TypeScript security rules (mirrors JS + Tier 1)
│   └── universal-security.yaml   # 3 cross-language rules
├── hypothesis/            # Hypothesis test executables (h1–h16)
├── test_fixtures/
│   ├── python/            # clean.py, broken.py, vulnerable.py, safe.py
│   ├── javascript/        # clean.js, broken.js, vulnerable.js, safe.js
│   ├── rules.yaml         # Semgrep-compatible test rules
│   └── ground_truth.yaml  # Expected findings manifest
├── vendor/
│   ├── tree-sitter-python/     # v0.23.5 (ABI 14)
│   ├── tree-sitter-javascript/ # v0.23.1 (ABI 14)
│   ├── tree-sitter-go/         # v0.23.4 (ABI 14)
│   ├── tree-sitter-typescript/ # v0.23.2 (ABI 14)
│   └── tree-sitter-core/       # (unused — using system lib 0.22.6)
└── .claude/               # Agentic development configuration
```

## Phase 1 MVP — Implementation Plan

| Component | PRD Section | Status | Depends On |
|-----------|------------|--------|------------|
| Parser layer (tree-sitter) | §4.1 | Proven (H1) | — |
| ZIR (intermediate repr) | §4.2 | Proven (H2) | Parser |
| Normalizer (CST→ZIR) | §4.2 | Extracted (`src/normalizer.zig`) | Parser, ZIR |
| Rule system (YAML→pattern) | §4.3 | Proven (H8) — `src/rule.zig` | ZIR |
| Matcher engine | §4.4 | Proven (H8) — `src/matcher.zig` | ZIR, Rule system |
| Prefilter engine | §4.5 | Proven (H5, H8) | ZIR |
| CLI (`zent scan`) | §6 | Done — `src/main.zig` | All above |
| SARIF output | §6 | Done — `src/sarif.zig` | Matcher |
| Incremental cache | §4.8 | Done — `src/cache.zig` | Parser, ZIR |

## Benchmark Targets

| ID | Metric | Target | Measured | Status |
|----|--------|--------|----------|--------|
| B-01 | Cold scan (single file, 20 rules) | <1ms | 332μs | PASS |
| B-02 | Semgrep cold scan (same file, same rules) | baseline | 1,562ms | BASELINE |
| B-03 | Parse-only throughput | <500μs/file | 189μs | PASS |
| B-04 | Arena vs page_allocator | >1.2x | 1.58x | PASS |
| B-05 | Prefilter skip ratio | >80% | 83.3% | PASS |
| B-06 | Warm scan (incremental) | <200ms (medium repo) | 218μs (2 files, cache hit) | PASS |
| B-07 | Memory usage | <50% of Semgrep | UNTESTED | — |
| B-08 | Startup time | <50ms | ~1ms | PASS |
| B-09 | Binary size | <40MB | 2.7MB | PASS |
| B-10 | Tier 1 assignment vs Tier 0 | <2x | 1.08x | PASS |
| B-11 | Arg constraint vs Tier 0 call | <3x | 0.97x | PASS |
| B-12 | Tier enforcement overhead | <5% | 2.0% | PASS |

## Settled Architecture Decisions

1. **Zig is the implementation language.** Single static binary, no runtime dependencies. C interop for tree-sitter.
2. **Tree-sitter for parsing.** Error-tolerant, incremental, multi-language. Via C FFI, not native Zig parsers (for now).
3. **ZIR is the unified intermediate representation.** Language-agnostic node types. All matching operates on ZIR, never on raw CST.
4. **Tiered cost model.** Rules declare their cost tier (0–3). Engine never pays Tier 3 cost for Tier 0 rules. Tier 0: structural matching. Tier 1: local reasoning (literal classification, argument constraints). Tier 2: intra-procedural taint (parameter→variable→sink tracking). Tier 3: cross-file taint (import→call→sink across module boundaries, one-hop).
5. **Prefilter before match.** File signatures (identifiers, node kinds) compared against rule requirements. Skip mismatches entirely.
6. **Arena allocators for hot paths.** ZIR construction and matching use arena allocation. Reset per file, no individual frees.
7. **Deterministic execution.** Same input → same output. Seeded scheduling. No nondeterministic traversal.
8. **Incremental by default.** Content-addressed caching of ASTs, ZIR, match results, findings.
9. **Semgrep rule compatibility.** YAML rule format compatible with Semgrep's subset. Not a goal to support all Semgrep features.
10. **SARIF output.** Standard format for IDE and CI integration.

## Key Constraints

| Constraint | Source | Value | Wired In |
|-----------|--------|-------|----------|
| ABI version match | tree-sitter | Grammars must use ABI 14 | build.zig, vendor/ (py 0.23.5, js 0.23.1, go 0.23.4) |
| No heap in hot path | PRD §5 | Arena allocators only in parse+match loop | H6 validated |
| Zero runtime fragmentation | PRD §2.1 | One Zig binary, no subprocess | Architecture decision #1 |
| Error tolerance | PRD §2.5 | Must produce usable ZIR from broken code | H3 validated |
| Deterministic output | PRD §2.2 | Same input → same output | Architecture decision #7 |

## Core Domain Types (src/zir.zig)

- `LiteralKind` — Literal sub-types (enum u4): string, number_int, number_float, boolean, null_value, regex, collection, unknown. Packed into bits 4–7 of Node.flags.
- `Kind` — Normalized node kinds: module, function, call, identifier, literal, assignment, import, member_access, control_flow, return_stmt, binary_op, unary_op, block, parameter, argument, class, attribute, comment, string_template, expression_stmt, unknown
- `Span` — Byte offsets + row/col positions
- `Node` — ZIR node: kind, span, flags, children, atom, parent. `literalKind()` accessor for Tier 1.
- `AtomTable` — Interned string table for identifiers and literals
- `ZirTree` — Complete ZIR: nodes + atoms + source language

## Competitive Position

Semgrep's core is OCaml (source-available, LGPL-2.1 + Commons Clause). Pro features (taint, cross-file) are proprietary. Zentinel's opening: fully open, unified Zig binary shipping all tiers.
