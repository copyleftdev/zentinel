/// Agent-optimized JSON output — structured findings for AI agent consumption.
///
/// Each finding includes:
///   - Exact location (file, line, col)
///   - Source context (the offending line + surrounding lines)
///   - Category tag (command-injection, hardcoded-secret, etc.)
///   - Confidence score (0.0-1.0)
///   - Fix suggestion (actionable remediation text)
///   - Severity as both string and numeric (for sorting)
const std = @import("std");
const matcher = @import("matcher");
const rule = @import("rule");

// ── Category Classification ──

const Category = struct {
    tag: []const u8,
    display: []const u8,
};

fn classifyCategory(rule_id: []const u8) Category {
    const id = rule_id;
    if (contains(id, "exec") and !contains(id, "deserializ")) return .{ .tag = "command-injection", .display = "Command Injection" };
    if (contains(id, "eval") or contains(id, "function-constructor") or contains(id, "settimeout") or contains(id, "setinterval")) return .{ .tag = "code-injection", .display = "Code Injection" };
    if (contains(id, "sql") or contains(id, "cursor")) return .{ .tag = "sql-injection", .display = "SQL Injection" };
    if (contains(id, "md5") or contains(id, "sha1") or contains(id, "crypto") or contains(id, "hash")) return .{ .tag = "weak-cryptography", .display = "Weak Cryptography" };
    if (contains(id, "secret") or contains(id, "hardcoded") or contains(id, "password") or contains(id, "key") or contains(id, "token")) return .{ .tag = "hardcoded-secret", .display = "Hardcoded Secret" };
    if (contains(id, "pickle") or contains(id, "marshal") or contains(id, "yaml-load") or contains(id, "shelve") or contains(id, "deserializ")) return .{ .tag = "unsafe-deserialization", .display = "Unsafe Deserialization" };
    if (contains(id, "innerhtml") or contains(id, "document.write") or contains(id, "xss")) return .{ .tag = "xss", .display = "Cross-Site Scripting" };
    if (contains(id, "http") or contains(id, "ssl") or contains(id, "tls") or contains(id, "ftp")) return .{ .tag = "insecure-network", .display = "Insecure Network" };
    if (contains(id, "tempfile")) return .{ .tag = "race-condition", .display = "Race Condition" };
    if (contains(id, "taint") or contains(id, "crossfile")) return .{ .tag = "tainted-data-flow", .display = "Tainted Data Flow" };
    return .{ .tag = "security", .display = "Security" };
}

// ── Confidence Scoring ──

fn confidenceScore(rule_id: []const u8, severity: rule.Severity) f64 {
    var score: f64 = switch (severity) {
        .ERROR => 0.9,
        .WARNING => 0.7,
        .INFO => 0.4,
    };
    // Tier 1+ rules are more precise
    if (contains(rule_id, "shell-true") or contains(rule_id, "fstring") or
        contains(rule_id, "precise") or contains(rule_id, "template") or
        contains(rule_id, "new-md5") or contains(rule_id, "new-sha1"))
        score = @min(score + 0.1, 1.0);
    // Taint rules have high confidence
    if (contains(rule_id, "taint")) score = @min(score + 0.15, 1.0);
    // Community rules are slightly lower confidence
    if (contains(rule_id, "community.")) score = @max(score - 0.15, 0.2);
    return score;
}

// ── Fix Suggestions ──

fn fixSuggestion(rule_id: []const u8) []const u8 {
    if (contains(rule_id, "exec-usage") or contains(rule_id, "exec-command")) return "Replace with a safer alternative. In Python, use subprocess.run() with shell=False. In Go, validate and sanitize all arguments to exec.Command().";
    if (contains(rule_id, "eval-usage") or contains(rule_id, "eval-template") or contains(rule_id, "eval-fstring")) return "Remove eval(). Parse structured data with json.loads() or ast.literal_eval(). Never evaluate user-controlled strings.";
    if (contains(rule_id, "subprocess") and contains(rule_id, "shell-true")) return "Set shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg1'], shell=False).";
    if (contains(rule_id, "subprocess")) return "Validate and sanitize all input. Prefer subprocess.run() with shell=False and explicit argument lists.";
    if (contains(rule_id, "os-system")) return "Replace os.system() with subprocess.run(cmd, shell=False). Never pass user input to os.system().";
    if (contains(rule_id, "pickle") or contains(rule_id, "marshal") or contains(rule_id, "shelve")) return "Use json or a safe serialization format instead. Never deserialize untrusted data with pickle/marshal.";
    if (contains(rule_id, "yaml-load")) return "Replace yaml.load() with yaml.safe_load() to prevent code execution from YAML input.";
    if (contains(rule_id, "md5") or contains(rule_id, "sha1")) return "Replace with SHA-256 or stronger: hashlib.sha256() in Python, crypto.createHash('sha256') in JS, sha256.Sum256() in Go.";
    if (contains(rule_id, "hardcoded-secret")) return "Move the secret to an environment variable or secrets manager. Use os.environ.get('KEY') in Python, process.env.KEY in JS, os.Getenv('KEY') in Go.";
    if (contains(rule_id, "innerhtml") or contains(rule_id, "document.write")) return "Use textContent or DOM APIs instead of innerHTML/document.write() to prevent XSS.";
    if (contains(rule_id, "sql-injection") or contains(rule_id, "cursor.execute")) return "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,)) instead of string formatting.";
    if (contains(rule_id, "ssl") or contains(rule_id, "verify")) return "Enable TLS certificate verification. Set verify=True for requests, use ssl.create_default_context().";
    if (contains(rule_id, "tempfile")) return "Replace tempfile.mktemp() with tempfile.mkstemp() to avoid TOCTOU race conditions.";
    if (contains(rule_id, "http-createserver")) return "Use HTTPS in production: require('https').createServer(options, handler).";
    if (contains(rule_id, "json-parse")) return "Wrap JSON.parse() in try/catch and validate the source of the input.";
    if (contains(rule_id, "process-exit")) return "Use graceful shutdown: close servers and flush buffers before calling process.exit().";
    if (contains(rule_id, "function-constructor")) return "Remove new Function(). Use named functions or arrow functions instead.";
    if (contains(rule_id, "settimeout") or contains(rule_id, "setinterval")) return "Pass a function reference instead of a string: setTimeout(myFunc, 1000) not setTimeout('myFunc()', 1000).";
    return "Review this finding and apply the appropriate security fix for your context.";
}

// ── JSON Output ──

pub fn writeAgentJson(
    writer: anytype,
    file_results: anytype,
    files_scanned: usize,
    duration_ms: f64,
    source_map: *const std.StringHashMap([]const u8),
) !void {
    try writer.writeAll("{");

    // Metadata
    try writer.print("\"scanner\":\"zentinel\",\"version\":\"0.4.1\",\"files_scanned\":{d},\"duration_ms\":{d:.1},", .{ files_scanned, duration_ms });

    // Summary
    var total: usize = 0;
    var errors: usize = 0;
    var warnings: usize = 0;
    var infos: usize = 0;
    for (file_results) |fr| {
        total += fr.findings.len;
        for (fr.findings) |f| {
            switch (f.severity) {
                .ERROR => errors += 1,
                .WARNING => warnings += 1,
                .INFO => infos += 1,
            }
        }
    }
    try writer.print("\"total_findings\":{d},\"errors\":{d},\"warnings\":{d},\"infos\":{d},", .{ total, errors, warnings, infos });

    // Findings array
    try writer.writeAll("\"findings\":[");
    var first = true;

    for (file_results) |fr| {
        for (fr.findings) |f| {
            if (!first) try writer.writeAll(",");
            first = false;

            const cat = classifyCategory(f.rule_id);
            const confidence = confidenceScore(f.rule_id, f.severity);
            const fix = fixSuggestion(f.rule_id);
            const sev_num: u8 = switch (f.severity) {
                .ERROR => 3,
                .WARNING => 2,
                .INFO => 1,
            };

            try writer.writeAll("{");
            try writer.print("\"file\":", .{});
            try writeJsonString(writer, fr.path);
            try writer.print(",\"line\":{d},\"col\":{d}", .{ f.span.start_row + 1, f.span.start_col + 1 });
            try writer.print(",\"end_line\":{d},\"end_col\":{d}", .{ f.span.end_row + 1, f.span.end_col + 1 });
            try writer.writeAll(",\"severity\":");
            try writeJsonString(writer, @tagName(f.severity));
            try writer.print(",\"severity_num\":{d}", .{sev_num});
            try writer.writeAll(",\"rule_id\":");
            try writeJsonString(writer, f.rule_id);
            try writer.writeAll(",\"category\":");
            try writeJsonString(writer, cat.tag);
            try writer.writeAll(",\"category_display\":");
            try writeJsonString(writer, cat.display);
            try writer.print(",\"confidence\":{d:.2}", .{confidence});
            try writer.writeAll(",\"message\":");
            try writeJsonString(writer, f.message);
            try writer.writeAll(",\"fix\":");
            try writeJsonString(writer, fix);

            // Source context
            if (source_map.get(fr.path)) |source| {
                try writer.writeAll(",\"context\":");
                try writeSourceContext(writer, source, f.span.start_row, f.span.end_row);
            }

            try writer.writeAll("}");
        }
    }

    try writer.writeAll("]}");
}

fn writeSourceContext(writer: anytype, source: []const u8, start_row: u32, end_row: u32) !void {
    try writer.writeAll("{");

    const context_before: u32 = 2;
    const context_after: u32 = 2;
    const first_row = if (start_row >= context_before) start_row - context_before else 0;
    const last_row = end_row + context_after;

    // Extract lines
    var row: u32 = 0;
    var line_start: usize = 0;
    var first_line = true;

    try writer.writeAll("\"lines\":[");

    for (source, 0..) |c, pos| {
        if (c == '\n' or pos == source.len - 1) {
            const line_end = if (c == '\n') pos else pos + 1;
            if (row >= first_row and row <= last_row) {
                if (!first_line) try writer.writeAll(",");
                first_line = false;
                try writer.print("{{\"num\":{d},\"text\":", .{row + 1});
                const line = source[line_start..line_end];
                try writeJsonString(writer, line);
                const is_finding = row >= start_row and row <= end_row;
                try writer.print(",\"highlight\":{}}}", .{is_finding});
            }
            row += 1;
            line_start = pos + 1;
            if (row > last_row) break;
        }
    }

    try writer.writeAll("]}");
}

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}
