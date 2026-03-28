/// H13: Do Tier 1 argument constraints produce precise matches?
///
/// PASS criteria:
///   1. subprocess.call(..., shell=True) matches when shell=True present, not otherwise
///   2. hashlib.new("md5") matches when arg is "md5", not "sha256"
///   3. eval(f"...") matches when arg is f-string, not plain string
///   4. Fast matcher agrees with linear matcher
///   5. Tier is auto-inferred to 1 for all constrained patterns
///   6. Cross-language: JavaScript template literal constraint works
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher_mod = @import("matcher");
const fast_matcher = @import("fast_matcher");

const Result = struct {
    name: []const u8,
    passed: bool,
    detail: []const u8,
};

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\
        \\══════════════════════════════════════════════════════════
        \\  H13: Argument Constraints (Tier 1)
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    var parser = try ts.Parser.init();
    defer parser.deinit();

    // ═══════════════════════════════════════════════════════
    // Test 1: Keyword argument — subprocess.call(..., shell=True)
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 1: Keyword arg (shell=True) ──\n");

    const py_subprocess_source =
        \\import subprocess
        \\subprocess.call("ls", shell=True)
        \\subprocess.call("ls")
        \\subprocess.run("cmd", shell=False)
    ;

    try parser.setLanguage(.python);
    var py_sub_tree = try parser.parse(py_subprocess_source);
    defer py_sub_tree.deinit();
    var py_sub_zir = zir.ZirTree.init(alloc, "python");
    defer py_sub_zir.deinit();
    try normalizer.buildZir(&py_sub_zir, &py_sub_tree.rootNode(), null, .python);

    const shell_true_yaml =
        \\rules:
        \\  - id: subprocess-shell-true
        \\    pattern: subprocess.call(..., shell=True)
        \\    message: shell=True is dangerous
        \\    languages: [python]
        \\    severity: ERROR
    ;
    const shell_rules = try rule.parseRules(shell_true_yaml, alloc);
    defer alloc.free(shell_rules);
    const shell_compiled = try rule.compileRules(shell_rules, alloc);
    defer alloc.free(shell_compiled);

    // Dump compiled pattern info
    for (shell_compiled) |cr| {
        try stdout.print("  Compiled: {s} tier={d} pattern={s}\n", .{
            cr.rule.id, cr.rule.tier, @tagName(cr.pattern),
        });
    }

    const shell_findings = try matcher_mod.matchRules(&py_sub_zir, shell_compiled, "python", alloc);
    defer alloc.free(shell_findings);

    for (shell_findings) |f| {
        try stdout.print("  Finding: {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
    }

    // Should match line 2 (shell=True) but NOT line 3 (no shell arg) or line 4 (shell=False, different function)
    try results.append(.{
        .name = "keyword_shell_true",
        .passed = shell_findings.len == 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{shell_findings.len}),
    });

    // Verify tier auto-inferred
    try results.append(.{
        .name = "keyword_tier_inferred",
        .passed = shell_compiled.len > 0 and shell_compiled[0].rule.tier == 1,
        .detail = try std.fmt.allocPrint(alloc, "tier={d}", .{if (shell_compiled.len > 0) shell_compiled[0].rule.tier else 255}),
    });

    // ═══════════════════════════════════════════════════════
    // Test 2: Exact string argument — hashlib.new("md5")
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 2: Exact string arg (\"md5\") ──\n");

    const py_hash_source =
        \\import hashlib
        \\hashlib.new("md5")
        \\hashlib.new("sha256")
        \\hashlib.new("sha1")
    ;

    var py_hash_tree = try parser.parse(py_hash_source);
    defer py_hash_tree.deinit();
    var py_hash_zir = zir.ZirTree.init(alloc, "python");
    defer py_hash_zir.deinit();
    try normalizer.buildZir(&py_hash_zir, &py_hash_tree.rootNode(), null, .python);

    const hash_yaml =
        \\rules:
        \\  - id: weak-hash-md5
        \\    pattern: hashlib.new("md5")
        \\    message: MD5 is cryptographically broken
        \\    languages: [python]
        \\    severity: ERROR
    ;
    const hash_rules = try rule.parseRules(hash_yaml, alloc);
    defer alloc.free(hash_rules);
    const hash_compiled = try rule.compileRules(hash_rules, alloc);
    defer alloc.free(hash_compiled);

    const hash_findings = try matcher_mod.matchRules(&py_hash_zir, hash_compiled, "python", alloc);
    defer alloc.free(hash_findings);

    for (hash_findings) |f| {
        try stdout.print("  Finding: {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
    }

    // Should match line 2 (md5) but NOT line 3 (sha256) or line 4 (sha1)
    try results.append(.{
        .name = "exact_string_md5",
        .passed = hash_findings.len == 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{hash_findings.len}),
    });

    // ═══════════════════════════════════════════════════════
    // Test 3: String template argument — eval(f"...")
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 3: String template arg (f-string) ──\n");

    const py_fstr_source =
        \\user = "alice"
        \\eval(f"select * from users where name = {user}")
        \\eval("safe_constant")
        \\eval(variable)
    ;

    var py_fstr_tree = try parser.parse(py_fstr_source);
    defer py_fstr_tree.deinit();
    var py_fstr_zir = zir.ZirTree.init(alloc, "python");
    defer py_fstr_zir.deinit();
    try normalizer.buildZir(&py_fstr_zir, &py_fstr_tree.rootNode(), null, .python);

    const fstr_yaml =
        \\rules:
        \\  - id: eval-fstring
        \\    pattern: eval(f"...")
        \\    message: eval with f-string is dangerous
        \\    languages: [python]
        \\    severity: ERROR
    ;
    const fstr_rules = try rule.parseRules(fstr_yaml, alloc);
    defer alloc.free(fstr_rules);
    const fstr_compiled = try rule.compileRules(fstr_rules, alloc);
    defer alloc.free(fstr_compiled);

    const fstr_findings = try matcher_mod.matchRules(&py_fstr_zir, fstr_compiled, "python", alloc);
    defer alloc.free(fstr_findings);

    for (fstr_findings) |f| {
        try stdout.print("  Finding: {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
    }

    // Should match line 2 (f-string eval) but NOT line 3 (safe string) or line 4 (variable)
    try results.append(.{
        .name = "fstring_eval",
        .passed = fstr_findings.len == 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{fstr_findings.len}),
    });

    // ═══════════════════════════════════════════════════════
    // Test 4: Fast matcher agrees with linear matcher
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 4: Fast vs linear matcher agreement ──\n");

    var shell_index = try fast_matcher.RuleIndex.build(shell_compiled, alloc);
    defer shell_index.deinit();
    const shell_fast = try fast_matcher.matchIndexed(&py_sub_zir, &shell_index, "python", alloc);
    defer alloc.free(shell_fast);

    var hash_index = try fast_matcher.RuleIndex.build(hash_compiled, alloc);
    defer hash_index.deinit();
    const hash_fast = try fast_matcher.matchIndexed(&py_hash_zir, &hash_index, "python", alloc);
    defer alloc.free(hash_fast);

    var fstr_index = try fast_matcher.RuleIndex.build(fstr_compiled, alloc);
    defer fstr_index.deinit();
    const fstr_fast = try fast_matcher.matchIndexed(&py_fstr_zir, &fstr_index, "python", alloc);
    defer alloc.free(fstr_fast);

    const all_agree = shell_fast.len == shell_findings.len and
        hash_fast.len == hash_findings.len and
        fstr_fast.len == fstr_findings.len;

    try stdout.print("  shell: fast={d} linear={d}\n", .{ shell_fast.len, shell_findings.len });
    try stdout.print("  hash:  fast={d} linear={d}\n", .{ hash_fast.len, hash_findings.len });
    try stdout.print("  fstr:  fast={d} linear={d}\n", .{ fstr_fast.len, fstr_findings.len });

    try results.append(.{
        .name = "fast_matches_linear",
        .passed = all_agree,
        .detail = try std.fmt.allocPrint(alloc, "all agree: {}", .{all_agree}),
    });

    // ═══════════════════════════════════════════════════════
    // Test 5: JavaScript template literal
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 5: JavaScript template literal ──\n");

    const js_source =
        \\const userId = 42;
        \\eval(`select * from users where id = ${userId}`);
        \\eval("safe string");
    ;

    try parser.setLanguage(.javascript);
    var js_tree = try parser.parse(js_source);
    defer js_tree.deinit();
    var js_zir = zir.ZirTree.init(alloc, "javascript");
    defer js_zir.deinit();
    try normalizer.buildZir(&js_zir, &js_tree.rootNode(), null, .javascript);

    const js_yaml =
        \\rules:
        \\  - id: eval-template
        \\    pattern: eval(f"...")
        \\    message: eval with template literal is dangerous
        \\    languages: [javascript]
        \\    severity: ERROR
    ;
    const js_rules = try rule.parseRules(js_yaml, alloc);
    defer alloc.free(js_rules);
    const js_compiled = try rule.compileRules(js_rules, alloc);
    defer alloc.free(js_compiled);

    const js_findings = try matcher_mod.matchRules(&js_zir, js_compiled, "javascript", alloc);
    defer alloc.free(js_findings);

    for (js_findings) |f| {
        try stdout.print("  Finding: {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
    }

    // Should match line 2 (template literal) but NOT line 3 (plain string)
    try results.append(.{
        .name = "javascript_template_literal",
        .passed = js_findings.len == 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{js_findings.len}),
    });

    try printResults(stdout, results.items);
}

fn printResults(writer: anytype, results_list: []const Result) !void {
    writer.writeAll("\n── Results ─────────────────────────────────────────────\n") catch return;
    var pass_count: u32 = 0;
    var fail_count: u32 = 0;
    for (results_list) |r| {
        const icon: []const u8 = if (r.passed) "PASS" else "FAIL";
        writer.print("  [{s}] {s}: {s}\n", .{ icon, r.name, r.detail }) catch return;
        if (r.passed) pass_count += 1 else fail_count += 1;
    }
    writer.print("\n  Total: {d} passed, {d} failed\n", .{ pass_count, fail_count }) catch return;
    const verdict: []const u8 = if (fail_count == 0) "H13 CONFIRMED" else "H13 NEEDS WORK";
    writer.print("  Verdict: {s}\n\n", .{verdict}) catch return;
}
