## What

<!-- One sentence: what does this PR do? -->

## Why

<!-- What problem does it solve? Link to issue if applicable. -->

## How to verify

- [ ] `zig build hypothesis` — all hypotheses pass
- [ ] `zig build run-h9_ground_truth` — ground truth validation passes
- [ ] Manual test: `zent scan test_fixtures/ --config rules/python-security.yaml`

## Checklist

- [ ] No new warnings from `zig build`
- [ ] Hypothesis tests pass (no regressions)
- [ ] CLAUDE.md updated (if architecture/benchmark/status changed)
- [ ] New rules include ground truth fixtures (if applicable)
