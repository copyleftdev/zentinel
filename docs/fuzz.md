---
layout: default
title: Fuzz Testing
nav_order: 7
---

# Fuzz Testing

Zentinel's hot paths are fuzzed with randomly generated inputs under Zig's safety checks (bounds, overflow, alignment). The initial campaign ran **1 billion inputs** with 0 crashes.

## Running the fuzzer

```bash
# Build (always Debug or ReleaseSafe — safety checks must be on)
zig build

# Fuzz a specific target with random inputs
zig build fuzz -- normalizer-js --gen 10000

# Fuzz with a corpus directory
zig build fuzz -- rules --corpus fuzz/corpus/yaml

# Single input from stdin
echo 'eval(x)' | zig build fuzz -- normalizer-py

# Run the full billion-input campaign
zig build fuzz -- billion
```

## Targets

### Integration targets (full pipeline, ~100 inputs/sec)

| Target | What it fuzzes |
|--------|---------------|
| `normalizer-py` | Arbitrary bytes → Python parse → ZIR |
| `normalizer-js` | Arbitrary bytes → JavaScript parse → ZIR |
| `rules` | Arbitrary bytes → YAML rule parser |
| `pattern` | Arbitrary bytes → pattern compiler |
| `matcher` | Arbitrary JS → full pipeline, differential: linear vs indexed matcher |
| `roundtrip` | Source → match → cache serialize → deserialize → compare |
| `cache` | Arbitrary bytes → cache deserializer |

### Micro targets (pure computation, millions/sec)

| Target | What it fuzzes | Rate |
|--------|---------------|------|
| `mapkind` | Random strings → node type dispatch | ~800K/sec |
| `simd` | Random hashes → SIMD vector search (checks SIMD vs scalar) | ~9.6M/sec |
| `patternfast` | Random strings → pattern compiler (tight loop) | ~3.4M/sec |
| `childindex` | Random ZIR trees → ChildIndex build + invariant checks | ~26K/sec |

### Billion campaign

`zig build fuzz -- billion` runs all micro targets with hardcoded counts totaling 1B inputs:

- mapkind: 300M
- simd: 300M
- patternfast: 200M
- childindex: 100M
- pattern: 50M
- rules: 50M

## Invariants checked

- **No crashes** on any input (the primary goal)
- **mapkind is deterministic** — same input always produces same Kind
- **SIMD matches scalar** — vector search and linear search agree
- **ChildIndex is complete** — total children equals total nodes with a parent
- **Matcher differential** — linear and indexed matcher produce identical findings
- **Cache roundtrip** — serialize then deserialize preserves finding count and rule IDs
- **Rule parser** — parsed rules always have non-empty IDs

## Bugs found

The fuzz campaign found 2 bugs in the YAML parser:

1. **Empty rule ID** — input with `- id:` and no value produced a rule with an empty ID. Fixed by skipping rules with empty IDs.
2. **Block scalar OOB** — `pattern: |` at end of input caused `block_start` to exceed buffer length. Fixed by clamping to source length.

Both were edge cases in the hand-written YAML parser. All other modules (normalizer, matcher, SIMD, ChildIndex, cache) survived the full campaign clean.

## Crash artifacts

If a fuzzer finds a crash, the input is saved to `fuzz/crashes/<tag>-<hash>.bin`. To reproduce:

```bash
zig build fuzz -- <target> < fuzz/crashes/some-crash.bin
```
