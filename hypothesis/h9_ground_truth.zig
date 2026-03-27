/// H9: Ground Truth Validation
///
/// Verifies that the rule corpus produces exactly the expected findings
/// against deterministic test fixtures:
///   - vulnerable files trigger every expected rule (zero false negatives)
///   - safe files trigger zero rules (zero false positives)
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher = @import("matcher");

const out = std.io.getStdOut().writer();

const TestCase = struct {
    file: []const u8,
    rules_file: []const u8,
    lang: ts.Language,
    lang_name: []const u8,
    expected_count: usize,
    expected_rules: []const []const u8,
    label: []const u8,
};

const cases = [_]TestCase{
    .{
        .file = "test_fixtures/python/vulnerable.py",
        .rules_file = "rules/python-security.yaml",
        .lang = .python,
        .lang_name = "python",
        .expected_count = 21,
        .expected_rules = &.{
            "python.security.exec-usage",
            "python.security.eval-usage",
            "python.security.os-system",
            "python.security.os-popen",
            "python.security.subprocess-shell",
            "python.security.subprocess-run",
            "python.security.subprocess-popen",
            "python.security.pickle-load",
            "python.security.pickle-loads",
            "python.security.yaml-load",
            "python.security.marshal-loads",
            "python.security.shelve-open",
            "python.security.hashlib-md5",
            "python.security.hashlib-sha1",
            "python.security.compile-usage",
            "python.security.input-python2",
            "python.security.ssl-no-verify",
            "python.security.requests-no-verify",
            "python.security.tempfile-mktemp",
            "python.security.hardcoded-secret",
        },
        .label = "Python vulnerable",
    },
    .{
        .file = "test_fixtures/python/safe.py",
        .rules_file = "rules/python-security.yaml",
        .lang = .python,
        .lang_name = "python",
        .expected_count = 0,
        .expected_rules = &.{},
        .label = "Python safe",
    },
    .{
        .file = "test_fixtures/javascript/vulnerable.js",
        .rules_file = "rules/javascript-security.yaml",
        .lang = .javascript,
        .lang_name = "javascript",
        .expected_count = 14,
        .expected_rules = &.{
            "javascript.security.eval-usage",
            "javascript.security.function-constructor",
            "javascript.security.settimeout-string",
            "javascript.security.setinterval-string",
            "javascript.security.exec-usage",
            "javascript.security.child-process-exec",
            "javascript.security.child-process-spawn",
            "javascript.security.innerhtml",
            "javascript.security.json-parse",
            "javascript.security.crypto-createhash-md5",
            "javascript.security.http-createserver",
            "javascript.security.hardcoded-secret",
            "javascript.security.process-exit",
        },
        .label = "JavaScript vulnerable",
    },
    .{
        .file = "test_fixtures/javascript/safe.js",
        .rules_file = "rules/javascript-security.yaml",
        .lang = .javascript,
        .lang_name = "javascript",
        .expected_count = 0,
        .expected_rules = &.{},
        .label = "JavaScript safe",
    },
};

pub fn main() !void {
    try out.writeAll("\n" ++ "=" ** 60 ++ "\n");
    try out.writeAll("  H9: Ground Truth Validation\n");
    try out.writeAll("=" ** 60 ++ "\n\n");

    const alloc = std.heap.page_allocator;
    var parser = try ts.Parser.init();
    defer parser.deinit();

    var pass_count: u32 = 0;
    var fail_count: u32 = 0;

    for (cases) |tc| {
        try out.print("── {s} ──\n", .{tc.label});

        // Load rules
        const yaml_source = try std.fs.cwd().readFileAlloc(alloc, tc.rules_file, 1024 * 1024);
        const rules = try rule.parseRules(yaml_source, alloc);
        const compiled = try rule.compileRules(rules, alloc);

        // Parse and normalize
        try parser.setLanguage(tc.lang);
        const source = try std.fs.cwd().readFileAlloc(alloc, tc.file, 1024 * 1024);
        var tree = try parser.parse(source);
        defer tree.deinit();
        var ztree = zir.ZirTree.init(alloc, tc.lang_name);
        try normalizer.buildZir(&ztree, &tree.rootNode(), null, tc.lang);

        // Match
        const findings = try matcher.matchRules(&ztree, compiled, tc.lang_name, alloc);

        // Check finding count
        const count_ok = findings.len == tc.expected_count;
        try out.print("  [{s}] count: got {d}, expected {d}\n", .{
            if (count_ok) "PASS" else "FAIL",
            findings.len,
            tc.expected_count,
        });
        if (count_ok) pass_count += 1 else fail_count += 1;

        // Check every expected rule fired at least once
        var rules_ok = true;
        for (tc.expected_rules) |expected_id| {
            var found = false;
            for (findings) |f| {
                if (std.mem.eql(u8, f.rule_id, expected_id)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                rules_ok = false;
                try out.print("  [FAIL] missing rule: {s}\n", .{expected_id});
            }
        }

        // Check no unexpected rules fired (false positives)
        for (findings) |f| {
            var expected = false;
            for (tc.expected_rules) |expected_id| {
                if (std.mem.eql(u8, f.rule_id, expected_id)) {
                    expected = true;
                    break;
                }
            }
            if (!expected) {
                rules_ok = false;
                try out.print("  [FAIL] unexpected finding: {s} @ {d}:{d}\n", .{
                    f.rule_id,
                    f.span.start_row + 1,
                    f.span.start_col + 1,
                });
            }
        }

        try out.print("  [{s}] rules: all expected rules {s}\n", .{
            if (rules_ok) "PASS" else "FAIL",
            if (rules_ok) "present, no unexpected" else "MISMATCH",
        });
        if (rules_ok) pass_count += 1 else fail_count += 1;

        try out.writeAll("\n");
    }

    // Verdict
    const total = pass_count + fail_count;
    try out.writeAll("── Results " ++ "─" ** 49 ++ "\n");
    try out.print("  Total: {d} passed, {d} failed (out of {d})\n", .{ pass_count, fail_count, total });
    const verdict: []const u8 = if (fail_count == 0) "H9 CONFIRMED" else "H9 NEEDS WORK";
    try out.print("  Verdict: {s}\n\n", .{verdict});
}
