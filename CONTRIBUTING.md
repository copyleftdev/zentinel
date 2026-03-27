# Contributing to Zentinel

## Getting started

```bash
# Clone and build
git clone https://github.com/your-org/zentinel.git
cd zentinel
zig build

# Run the test suite
zig build hypothesis

# Run a scan
./zig-out/bin/zent scan test_fixtures/python/vulnerable.py --config rules/python-security.yaml
```

Requires [Zig 0.14](https://ziglang.org/download/) and a system `tree-sitter` library (0.22+).

## What to work on

Check the [issues](../../issues) for open work. Good starting points:

- **New rules** — add detection patterns to `rules/`. See the "New Rule" issue template.
- **New language** — follow the steps in `CLAUDE.md` under "Adding a New Language."
- **Bug fixes** — especially anything found by the fuzzer.

## Adding a rule

1. Add the rule to the appropriate YAML file in `rules/`.
2. Add a trigger line to the vulnerable fixture (`test_fixtures/<lang>/vulnerable.<ext>`).
3. Update the expected count in `hypothesis/h9_ground_truth.zig`.
4. Run `zig build run-h9_ground_truth` to verify.

## Adding a language

1. Find a tree-sitter grammar with ABI version 14.
2. Vendor it into `vendor/tree-sitter-<language>/`.
3. Add it to `build.zig` (static library + link).
4. Add a `Language` variant to `src/treesitter.zig`.
5. Add `mapKind` cases in `src/normalizer.zig`.
6. Write test fixtures (clean, broken, vulnerable, safe).
7. Verify with `zig build hypothesis`.

## Code style

- `zig fmt` everything.
- `const` over `var`.
- Error unions, not panics.
- No heap allocation in the match loop — arena only.

## Testing

Every PR must pass:

```bash
zig build hypothesis    # All 10 hypotheses confirmed
```

For performance work, run the benchmark:

```bash
zig build -Doptimize=ReleaseFast run-h10_indexed_matcher
```

For fuzz testing:

```bash
zig build fuzz -- <target> --gen 10000
```

## Commit style

Short subject line. Body explains why, not what. One logical change per commit.
