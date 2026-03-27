# Security Policy

## Reporting a vulnerability

If you find a security issue in Zentinel itself (not a detection rule), please report it privately.

**Email:** security@zentinel.dev

Do not open a public issue for security vulnerabilities. We will acknowledge receipt within 48 hours and provide a fix timeline within 7 days.

## Scope

This policy covers:

- Crashes or panics from malformed input (source files, YAML rules, cache files)
- Memory safety issues (buffer overflows, use-after-free)
- Denial of service (inputs that cause unbounded resource consumption)
- False negatives in security rules (a rule that should fire but doesn't)

Out of scope:

- False positives (rules firing on safe code) — file a regular bug report
- Feature requests for new rules — use the "New Rule" issue template

## Supported versions

Only the latest release is supported with security fixes.

## Fuzzing

Zentinel's hot paths are continuously fuzzed. If you find a crash, the fastest way to report it is to include the minimal input that triggers it. See `fuzz/` for the harness.
