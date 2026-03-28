/// H8: Rule System — End-to-end: YAML → compile → match → findings
///
/// Tests:
///   8.1 Parse rules.yaml (5 rules loaded)
///   8.2 Compile patterns (at least 3 compile — unsupported ones skipped)
///   8.3 Match Python fixture → find dangerous-exec, dangerous-eval, hardcoded-secret
///   8.4 Match JavaScript fixture → find dangerous-exec, dangerous-eval, hardcoded-secret
///   8.5 Zero false positives (no python-only rules match JS, etc.)
///   8.6 Prefilter correctly filters (subprocess.call rule skipped for JS)
///   8.7 Cross-language: same rule ID matches in both Python and JS
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher = @import("matcher");

const out = std.io.getStdOut().writer();

pub fn main() !void {
    try out.print("\n" ++ "=" ** 60 ++ "\n", .{});
    try out.print(" H8: Rule System (YAML → Compile → Match → Findings)\n", .{});
    try out.print("=" ** 60 ++ "\n\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Load rules.yaml at runtime
    const yaml_source = try std.fs.cwd().readFileAlloc(allocator, "test_fixtures/rules.yaml", 64 * 1024);
    defer allocator.free(yaml_source);

    // ── Test 8.1: Parse YAML ──
    const rules = try rule.parseRules(yaml_source, allocator);
    defer allocator.free(rules);
    const t8_1 = rules.len == 5;
    try printResult("8.1", "Parse rules.yaml (5 rules)", t8_1, std.fmt.allocPrint(allocator, "got {d} rules", .{rules.len}) catch "?");

    // Print parsed rules
    for (rules) |r| {
        try out.print("  Rule: {s} | pattern: '{s}' | severity: {s}\n", .{
            r.id,
            r.pattern_source,
            @tagName(r.severity),
        });
    }
    try out.print("\n", .{});

    // ── Test 8.2: Compile patterns ──
    const compiled = try rule.compileRules(rules, allocator);
    defer allocator.free(compiled);
    const t8_2 = compiled.len >= 3;
    try printResult("8.2", "Compile patterns (>=3 succeed)", t8_2, std.fmt.allocPrint(allocator, "{d}/{d} compiled", .{ compiled.len, rules.len }) catch "?");

    for (compiled) |cr| {
        const pat_type: []const u8 = switch (cr.pattern) {
            .call => "call",
            .assignment => "assignment",
            .member_call => "member_call",
            .call_with_args => "call_with_args",
            .member_call_with_args => "member_call_with_args",
        };
        try out.print("  Compiled: {s} → {s}\n", .{ cr.rule.id, pat_type });
    }
    try out.print("\n", .{});

    // ── Build ZIR trees for test fixtures ──
    const py_source = try std.fs.cwd().readFileAlloc(allocator, "test_fixtures/python/clean.py", 64 * 1024);
    defer allocator.free(py_source);
    const js_source = try std.fs.cwd().readFileAlloc(allocator, "test_fixtures/javascript/clean.js", 64 * 1024);
    defer allocator.free(js_source);

    // Python
    var py_parser = try ts.Parser.init();
    defer py_parser.deinit();
    try py_parser.setLanguage(.python);
    var py_tree = try py_parser.parse(py_source);
    defer py_tree.deinit();
    var py_zir = zir.ZirTree.init(allocator, "python");
    defer py_zir.deinit();
    try normalizer.buildZir(&py_zir, &py_tree.rootNode(), null, .python);

    // JavaScript
    var js_parser = try ts.Parser.init();
    defer js_parser.deinit();
    try js_parser.setLanguage(.javascript);
    var js_tree = try js_parser.parse(js_source);
    defer js_tree.deinit();
    var js_zir = zir.ZirTree.init(allocator, "javascript");
    defer js_zir.deinit();
    try normalizer.buildZir(&js_zir, &js_tree.rootNode(), null, .javascript);

    // ── Test 8.3: Match Python fixture ──
    const py_findings = try matcher.matchRules(&py_zir, compiled, "python", allocator);
    defer allocator.free(py_findings);

    const py_has_exec = hasFinding(py_findings, "dangerous-exec");
    const py_has_eval = hasFinding(py_findings, "dangerous-eval");
    const py_has_secret = hasFinding(py_findings, "hardcoded-secret");
    const t8_3 = py_has_exec and py_has_eval and py_has_secret;
    try printResult("8.3", "Python: exec + eval + secret found", t8_3, std.fmt.allocPrint(allocator, "exec={} eval={} secret={} (total {d})", .{ py_has_exec, py_has_eval, py_has_secret, py_findings.len }) catch "?");

    for (py_findings) |f| {
        try out.print("  Finding: {s} @ {d}:{d} [{s}]\n", .{
            f.rule_id,
            f.span.start_row + 1,
            f.span.start_col,
            @tagName(f.severity),
        });
    }
    try out.print("\n", .{});

    // ── Test 8.4: Match JavaScript fixture ──
    const js_findings = try matcher.matchRules(&js_zir, compiled, "javascript", allocator);
    defer allocator.free(js_findings);

    const js_has_exec = hasFinding(js_findings, "dangerous-exec");
    const js_has_eval = hasFinding(js_findings, "dangerous-eval");
    const js_has_secret = hasFinding(js_findings, "hardcoded-secret");
    const t8_4 = js_has_exec and js_has_eval and js_has_secret;
    try printResult("8.4", "JavaScript: exec + eval + secret found", t8_4, std.fmt.allocPrint(allocator, "exec={} eval={} secret={} (total {d})", .{ js_has_exec, js_has_eval, js_has_secret, js_findings.len }) catch "?");

    for (js_findings) |f| {
        try out.print("  Finding: {s} @ {d}:{d} [{s}]\n", .{
            f.rule_id,
            f.span.start_row + 1,
            f.span.start_col,
            @tagName(f.severity),
        });
    }
    try out.print("\n", .{});

    // ── Test 8.5: No false positives ──
    // subprocess-shell-true should NOT match in JS (languages: [python] only)
    const js_has_subprocess = hasFinding(js_findings, "subprocess-shell-true");
    const t8_5 = !js_has_subprocess;
    try printResult("8.5", "No false positives (subprocess rule not in JS)", t8_5, std.fmt.allocPrint(allocator, "subprocess_in_js={}", .{js_has_subprocess}) catch "?");

    // ── Test 8.6: Prefilter works ──
    // Build a signature for JS and check that subprocess prefilter fails
    var js_sig = try matcher.buildSignature(&js_zir, allocator);
    defer js_sig.deinit();
    var prefilter_skipped: u32 = 0;
    var prefilter_passed: u32 = 0;
    for (compiled) |cr| {
        var passes = true;
        for (cr.prefilter.required_kinds) |k| {
            if (!js_sig.kinds.contains(k)) {
                passes = false;
                break;
            }
        }
        if (passes) {
            for (cr.prefilter.required_atoms) |a| {
                if (!js_sig.identifiers.contains(a)) {
                    passes = false;
                    break;
                }
            }
        }
        if (passes) prefilter_passed += 1 else prefilter_skipped += 1;
    }
    const t8_6 = prefilter_skipped > 0;
    try printResult("8.6", "Prefilter skips at least 1 rule", t8_6, std.fmt.allocPrint(allocator, "passed={d} skipped={d}", .{ prefilter_passed, prefilter_skipped }) catch "?");

    // ── Test 8.7: Cross-language same rule matches both ──
    const cross_exec = py_has_exec and js_has_exec;
    const cross_eval = py_has_eval and js_has_eval;
    const cross_secret = py_has_secret and js_has_secret;
    const t8_7 = cross_exec and cross_eval and cross_secret;
    try printResult("8.7", "Cross-language: same rules match both", t8_7, std.fmt.allocPrint(allocator, "exec={} eval={} secret={}", .{ cross_exec, cross_eval, cross_secret }) catch "?");

    // ── Verdict ──
    const all_pass = t8_1 and t8_2 and t8_3 and t8_4 and t8_5 and t8_6 and t8_7;
    const pass_count = @as(u32, @intFromBool(t8_1)) + @as(u32, @intFromBool(t8_2)) +
        @as(u32, @intFromBool(t8_3)) + @as(u32, @intFromBool(t8_4)) +
        @as(u32, @intFromBool(t8_5)) + @as(u32, @intFromBool(t8_6)) +
        @as(u32, @intFromBool(t8_7));

    try out.print("\n" ++ "=" ** 60 ++ "\n", .{});
    try out.print("Verdict: H8 {s} ({d}/7 tests passed)\n", .{
        if (all_pass) "CONFIRMED" else "NEEDS WORK",
        pass_count,
    });
    try out.print("=" ** 60 ++ "\n", .{});
}

fn hasFinding(findings: []const matcher.Finding, rule_id: []const u8) bool {
    for (findings) |f| {
        if (std.mem.eql(u8, f.rule_id, rule_id)) return true;
    }
    return false;
}

fn printResult(id: []const u8, desc: []const u8, pass: bool, detail: []const u8) !void {
    try out.print("[{s}] {s}: {s}\n", .{
        if (pass) "PASS" else "FAIL",
        id,
        desc,
    });
    try out.print("       {s}\n", .{detail});
}
