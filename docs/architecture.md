---
layout: default
title: Architecture
nav_order: 6
---

# Architecture

## Pipeline

```
Source → tree-sitter → CST → Normalizer → ZIR → Prefilter → Matcher → Findings → SARIF
                                                     ↑
                                              Rule Index (SIMD)
```

Every scan follows this pipeline. Each stage has a clear input and output. No stage reaches across boundaries.

## ZIR — Zentinel Intermediate Representation

The core abstraction. ZIR is a language-agnostic syntax tree with normalized node types.

```
module
├── import
├── function
│   ├── identifier "run_command"
│   ├── parameter
│   └── block
│       └── call
│           ├── identifier "exec"
│           └── argument
└── assignment
    ├── identifier "SECRET_KEY"
    └── literal "hardcoded_secret"
```

Every language normalizes to the same ZIR kinds:

| Kind | Meaning |
|------|---------|
| `module` | Top-level program |
| `function` | Function/method declaration |
| `call` | Function call |
| `identifier` | Name reference |
| `literal` | String, number, bool |
| `assignment` | Variable assignment |
| `import` | Import/require |
| `member_access` | `a.b` property access |
| `control_flow` | if/for/while/try |
| `block` | Code block |

All matching operates on ZIR. Adding a new language means writing a `mapKind` function that maps tree-sitter node types to ZIR kinds. Nothing else changes.

## Modules

| File | Purpose |
|------|---------|
| `treesitter.zig` | Tree-sitter C FFI bindings |
| `zir.zig` | ZIR type definitions |
| `normalizer.zig` | CST → ZIR conversion (iterative, handles any depth) |
| `rule.zig` | YAML parser, pattern compiler, prefilter extraction |
| `matcher.zig` | Linear rule matcher |
| `fast_matcher.zig` | Indexed matcher with SIMD + ChildIndex |
| `cache.zig` | Content-addressed incremental cache |
| `sarif.zig` | SARIF v2.1.0 output |
| `main.zig` | CLI entry point |

## Key design decisions

**Tree-sitter for parsing.** Error-tolerant, incremental, multi-language. Zentinel gets broken-code resilience for free.

**ZIR as the contract.** All analysis operates on ZIR, never on raw CST. This makes the matcher language-agnostic.

**Tiered cost model.** Rules are classified by analysis complexity. Tier 0 (structural matching) runs in microseconds. Higher tiers (dataflow, taint) come later without slowing down simple rules.

**Arena allocators.** The parse → normalize → match hot path uses arena allocation. Reset per file, no individual frees. 1.58x faster than the system allocator.

**Iterative normalization.** The CST → ZIR walker uses an explicit stack instead of recursion. Handles arbitrarily deep trees (minified JavaScript) without stack overflow.

**Deterministic execution.** Same input + same rules = identical output. No nondeterministic traversal, no random scheduling.
