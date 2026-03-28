/// Secret detection heuristics — entropy analysis + known pattern matching.
///
/// Two-gate system for hardcoded secret detection:
///   Gate 1: Variable name contains a secret keyword (key, token, password, etc.)
///   Gate 2: Value looks like a secret (high entropy OR matches a known pattern)
///
/// Both gates must pass to produce a finding.
const std = @import("std");

// ── Shannon Entropy ──

/// Calculate Shannon entropy of a byte string (bits per character).
/// Real secrets: ~3.5-4.5 bits/char. Variable names: ~2.5-3.2 bits/char.
/// Threshold: 3.5 bits separates most secrets from normal strings.
pub fn shannonEntropy(data: []const u8) f64 {
    if (data.len == 0) return 0.0;

    var counts: [256]u32 = [_]u32{0} ** 256;
    for (data) |b| counts[b] += 1;

    var entropy: f64 = 0.0;
    const len_f: f64 = @floatFromInt(data.len);

    for (counts) |c| {
        if (c == 0) continue;
        const p: f64 = @as(f64, @floatFromInt(c)) / len_f;
        entropy -= p * @log2(p);
    }

    return entropy;
}

/// Minimum entropy for a value to be considered a potential secret.
pub const ENTROPY_THRESHOLD: f64 = 3.5;

/// Minimum length for entropy analysis to be meaningful.
pub const MIN_SECRET_LENGTH: usize = 6;

// ── Known Secret Patterns ──

/// Check if a string value matches known secret/API key patterns.
/// Based on patterns from gitleaks, truffleHog, and detect-secrets.
pub fn matchesKnownPattern(value: []const u8) bool {
    if (value.len < 8) return false;

    // Strip surrounding quotes if present
    const v = stripQuotes(value);
    if (v.len < 8) return false;

    // AWS
    if (startsWith(v, "AKIA")) return true; // AWS Access Key
    if (startsWith(v, "ASIA")) return true; // AWS STS
    if (startsWith(v, "AIDA")) return true; // AWS IAM
    if (startsWith(v, "AROA")) return true; // AWS Role
    if (startsWith(v, "AGPA")) return true; // AWS Group

    // GitHub
    if (startsWith(v, "ghp_")) return true; // Personal access token
    if (startsWith(v, "gho_")) return true; // OAuth
    if (startsWith(v, "ghu_")) return true; // User-to-server
    if (startsWith(v, "ghs_")) return true; // Server-to-server
    if (startsWith(v, "ghr_")) return true; // Refresh token
    if (startsWith(v, "github_pat_")) return true;

    // Stripe
    if (startsWith(v, "sk_live_")) return true;
    if (startsWith(v, "sk_test_")) return true;
    if (startsWith(v, "rk_live_")) return true;
    if (startsWith(v, "rk_test_")) return true;
    if (startsWith(v, "pk_live_")) return true;
    if (startsWith(v, "pk_test_")) return true;

    // Slack
    if (startsWith(v, "xoxb-")) return true;
    if (startsWith(v, "xoxp-")) return true;
    if (startsWith(v, "xoxs-")) return true;
    if (startsWith(v, "xoxa-")) return true;

    // OpenAI / Anthropic / AI
    if (startsWith(v, "sk-")) return true; // OpenAI, general secret key prefix
    if (startsWith(v, "sk-ant-")) return true; // Anthropic
    if (startsWith(v, "hf_")) return true; // Hugging Face
    if (startsWith(v, "AIza")) return true; // Google AI

    // Twilio
    if (startsWith(v, "SK") and v.len == 34 and isHex(v[2..])) return true;

    // Sendgrid
    if (startsWith(v, "SG.")) return true;

    // NPM
    if (startsWith(v, "npm_")) return true;

    // PyPI
    if (startsWith(v, "pypi-")) return true;

    // Discord
    if (v.len > 50 and containsChar(v, '.') and isBase64ish(v)) return true;

    // Generic patterns
    if (startsWith(v, "Bearer ")) return true;
    if (startsWith(v, "Basic ") and v.len > 20) return true;
    if (startsWith(v, "token-")) return true;
    if (startsWith(v, "api-")) return true;

    // JWT-shaped (three dot-separated base64 segments)
    if (isJWTShaped(v)) return true;

    // Long hex string (>= 32 chars, common for hashes/keys)
    if (v.len >= 32 and isHex(v)) return true;

    // Long base64 (>= 20 chars with base64 alphabet)
    if (v.len >= 20 and isBase64ish(v)) return true;

    return false;
}

/// Full secret check: name gate + value gate.
/// Returns true if the assignment looks like a hardcoded secret.
pub fn looksLikeSecret(name: []const u8, value: []const u8) bool {
    // Gate 1: name must contain a secret keyword
    if (!nameContainsSecretKeyword(name)) return false;

    // Gate 2: value must look like a secret
    const v = stripQuotes(value);
    if (v.len < MIN_SECRET_LENGTH) return false;

    // Known pattern match (high confidence — always accept)
    if (matchesKnownPattern(value)) return true;

    // High-confidence name keywords get a lower entropy bar
    // "password" and "secret" as variable names almost always mean the value IS a secret
    const is_high_confidence_name = containsInsensitive(name, "password") or
        containsInsensitive(name, "passwd") or
        containsInsensitive(name, "secret") or
        containsInsensitive(name, "credential");

    const threshold = if (is_high_confidence_name) 2.0 else ENTROPY_THRESHOLD;

    if (shannonEntropy(v) >= threshold) return true;

    return false;
}

// ── Name Keywords ──

const SECRET_KEYWORDS = [_][]const u8{
    "secret", "password", "passwd", "token", "credential",
    "auth", "api_key", "apikey", "private_key", "privatekey",
    "access_key", "accesskey", "cert",
};

pub fn nameContainsSecretKeyword(name: []const u8) bool {
    for (SECRET_KEYWORDS) |kw| {
        if (containsInsensitive(name, kw)) return true;
    }
    // Also match if name ends with _KEY or _key (suffix match, not substring)
    if (name.len >= 4) {
        const suffix = name[name.len - 4 ..];
        if (eqlInsensitive(suffix, "_key")) return true;
    }
    if (name.len >= 3) {
        const suffix = name[name.len - 3 ..];
        if (eqlInsensitive(suffix, "key")) return true;
    }
    return false;
}

// ── Helpers ──

fn stripQuotes(v: []const u8) []const u8 {
    if (v.len >= 2 and (v[0] == '"' or v[0] == '\'' or v[0] == '`')) {
        return v[1 .. v.len - 1];
    }
    return v;
}

fn startsWith(haystack: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, haystack, prefix);
}

fn isHex(s: []const u8) bool {
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'))) return false;
    }
    return true;
}

fn isBase64ish(s: []const u8) bool {
    var alnum: usize = 0;
    for (s) |c| {
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '+' or c == '/' or c == '=' or c == '-' or c == '_') {
            alnum += 1;
        }
    }
    return alnum * 100 / s.len >= 85; // 85%+ base64-like chars
}

fn containsChar(s: []const u8, c: u8) bool {
    return std.mem.indexOfScalar(u8, s, c) != null;
}

fn isJWTShaped(v: []const u8) bool {
    // JWT: header.payload.signature (three base64url segments separated by dots)
    var dots: usize = 0;
    for (v) |c| {
        if (c == '.') dots += 1;
    }
    return dots == 2 and v.len >= 30;
}

fn containsInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (0..needle.len) |j| {
            if (toLower(haystack[i + j]) != toLower(needle[j])) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

fn eqlInsensitive(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (toLower(ac) != toLower(bc)) return false;
    }
    return true;
}

fn toLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}
