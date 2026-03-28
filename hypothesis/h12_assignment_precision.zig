/// H12: Does Tier 1 assignment matching only fire on string literal RHS?
///
/// PASS criteria:
///   1. $KEY = "..." matches `API_KEY = "secret"` (string RHS)
///   2. $KEY = "..." does NOT match `count = 42` (integer RHS)
///   3. $KEY = "..." does NOT match `flag = True` (boolean RHS)
///   4. $KEY = "..." does NOT match `nothing = None` (null RHS)
///   5. Tier 1 findings < Tier 0 findings (more precise)
///   6. Fast matcher agrees with linear matcher
///   7. Tier field is auto-inferred for assignment patterns with "..."
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
        \\  H12: Assignment Precision (Tier 1)
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    // Test fixture: mix of assignment types
    const py_source =
        \\API_KEY = "sk-secret-1234"
        \\DB_PASSWORD = "hunter2"
        \\count = 42
        \\rate = 3.14
        \\flag = True
        \\nothing = None
        \\items = [1, 2, 3]
        \\name = "Alice"
    ;

    // Parse to ZIR
    var parser = try ts.Parser.init();
    defer parser.deinit();
    try parser.setLanguage(.python);
    var tree = try parser.parse(py_source);
    defer tree.deinit();

    var ztree = zir.ZirTree.init(alloc, "python");
    defer ztree.deinit();
    try normalizer.buildZir(&ztree, &tree.rootNode(), null, .python);

    // Dump assignment nodes for inspection
    try stdout.writeAll("\n── Assignment Nodes ─���\n");
    for (ztree.nodes.items, 0..) |node, idx| {
        if (node.kind == .assignment) {
            try stdout.print("  [{d}] assignment", .{idx});
            // Find child literals
            for (ztree.nodes.items) |child| {
                if (child.parent) |pid| {
                    if (pid == idx) {
                        if (child.kind == .identifier) {
                            if (child.atom) |aid| try stdout.print(" id={s}", .{ztree.atoms.get(aid)});
                        }
                        if (child.kind == .literal) {
                            const lk_name = if (child.literalKind()) |lk| @tagName(lk) else "?";
                            if (child.atom) |aid| {
                                try stdout.print(" lit={s}({s})", .{ ztree.atoms.get(aid), lk_name });
                            } else {
                                try stdout.print(" lit=({s})", .{lk_name});
                            }
                        }
                    }
                }
            }
            try stdout.writeAll("\n");
        }
    }

    // Rule: $KEY = "..." — should auto-infer tier=1
    const yaml_source =
        \\rules:
        \\  - id: hardcoded-secret
        \\    pattern: $KEY = "..."
        \\    message: Possible hardcoded secret
        \\    languages: [python]
        \\    severity: WARNING
    ;

    const rules = try rule.parseRules(yaml_source, alloc);
    defer alloc.free(rules);

    const compiled = try rule.compileRules(rules, alloc);
    defer alloc.free(compiled);

    // Test 7: Auto-inferred tier
    try stdout.writeAll("\n── Compiled Rules ──\n");
    for (compiled) |cr| {
        try stdout.print("  {s}: tier={d}, pattern={s}\n", .{
            cr.rule.id,
            cr.rule.tier,
            @tagName(cr.pattern),
        });
    }

    const tier_ok = compiled.len > 0 and compiled[0].rule.tier == 1;
    try results.append(.{
        .name = "tier_auto_inferred",
        .passed = tier_ok,
        .detail = try std.fmt.allocPrint(alloc, "tier={d} (expected 1)", .{if (compiled.len > 0) compiled[0].rule.tier else 255}),
    });

    // Run linear matcher
    const linear_findings = try matcher_mod.matchRules(&ztree, compiled, "python", alloc);
    defer alloc.free(linear_findings);

    try stdout.writeAll("\n── Linear Matcher Findings ──\n");
    for (linear_findings) |f| {
        try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
    }

    // Run fast matcher
    var rule_index = try fast_matcher.RuleIndex.build(compiled, alloc);
    defer rule_index.deinit();
    const fast_findings = try fast_matcher.matchIndexed(&ztree, &rule_index, "python", alloc);
    defer alloc.free(fast_findings);

    try stdout.writeAll("\n── Fast Matcher Findings ──\n");
    for (fast_findings) |f| {
        try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
    }

    // Expected: 3 string assignments (API_KEY, DB_PASSWORD, name)
    // Should NOT match: count=42, rate=3.14, flag=True, nothing=None, items=[1,2,3]

    // Test 1: Matches string assignments
    try results.append(.{
        .name = "matches_string_assignments",
        .passed = linear_findings.len == 3,
        .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 3: API_KEY, DB_PASSWORD, name)", .{linear_findings.len}),
    });

    // Test 2: Does not match integer assignment (count = 42)
    const has_count = hasRuleAtRow(linear_findings, 3);
    try results.append(.{
        .name = "rejects_integer_assignment",
        .passed = !has_count,
        .detail = try std.fmt.allocPrint(alloc, "count=42 matched: {}", .{has_count}),
    });

    // Test 3: Does not match boolean assignment (flag = True)
    const has_flag = hasRuleAtRow(linear_findings, 5);
    try results.append(.{
        .name = "rejects_boolean_assignment",
        .passed = !has_flag,
        .detail = try std.fmt.allocPrint(alloc, "flag=True matched: {}", .{has_flag}),
    });

    // Test 4: Does not match null assignment (nothing = None)
    const has_none = hasRuleAtRow(linear_findings, 6);
    try results.append(.{
        .name = "rejects_null_assignment",
        .passed = !has_none,
        .detail = try std.fmt.allocPrint(alloc, "nothing=None matched: {}", .{has_none}),
    });

    // Test 5: Compare against Tier 0 — compile without literal-kind constraint
    // Build a Tier 0 variant (rhs_literal_kind = null) to compare
    const tier0_rule_yaml =
        \\rules:
        \\  - id: hardcoded-secret-t0
        \\    pattern: $KEY = "..."
        \\    message: Tier 0 test
        \\    languages: [python]
        \\    severity: WARNING
    ;
    const t0_rules = try rule.parseRules(tier0_rule_yaml, alloc);
    defer alloc.free(t0_rules);

    // Manually compile without literal-kind to simulate Tier 0
    var t0_compiled_list = std.ArrayList(rule.CompiledRule).init(alloc);
    defer alloc.free(t0_compiled_list.items);
    for (t0_rules) |r| {
        const pattern = rule.CompiledPattern{ .assignment = .{
            .lhs_is_metavar = true,
            .rhs_is_string_literal = true,
            .rhs_literal_kind = null, // Tier 0: no literal-kind check
        } };
        const prefilter = try rule.extractPrefilter(pattern, alloc);
        try t0_compiled_list.append(.{ .rule = r, .pattern = pattern, .prefilter = prefilter });
    }
    const t0_compiled = t0_compiled_list.items;
    const t0_findings = try matcher_mod.matchRules(&ztree, t0_compiled, "python", alloc);
    defer alloc.free(t0_findings);

    try stdout.print("\n── Tier 0 (no literal-kind check): {d} findings\n", .{t0_findings.len});
    try stdout.print("── Tier 1 (string-only):            {d} findings\n", .{linear_findings.len});

    try results.append(.{
        .name = "tier1_more_precise",
        .passed = linear_findings.len < t0_findings.len,
        .detail = try std.fmt.allocPrint(alloc, "Tier 1: {d} < Tier 0: {d}", .{ linear_findings.len, t0_findings.len }),
    });

    // Test 6: Fast matcher agrees with linear matcher
    try results.append(.{
        .name = "fast_matches_linear",
        .passed = fast_findings.len == linear_findings.len,
        .detail = try std.fmt.allocPrint(alloc, "fast={d}, linear={d}", .{ fast_findings.len, linear_findings.len }),
    });

    // ── JavaScript test: same discrimination ──
    const js_source =
        \\const SECRET = "my-secret";
        \\const PORT = 3000;
        \\const DEBUG = true;
    ;

    try parser.setLanguage(.javascript);
    var js_tree = try parser.parse(js_source);
    defer js_tree.deinit();

    var js_ztree = zir.ZirTree.init(alloc, "javascript");
    defer js_ztree.deinit();
    try normalizer.buildZir(&js_ztree, &js_tree.rootNode(), null, .javascript);

    const js_yaml =
        \\rules:
        \\  - id: hardcoded-secret
        \\    pattern: $KEY = "..."
        \\    message: Possible hardcoded secret
        \\    languages: [javascript]
        \\    severity: WARNING
    ;
    const js_rules = try rule.parseRules(js_yaml, alloc);
    defer alloc.free(js_rules);
    const js_compiled = try rule.compileRules(js_rules, alloc);
    defer alloc.free(js_compiled);

    const js_findings = try matcher_mod.matchRules(&js_ztree, js_compiled, "javascript", alloc);
    defer alloc.free(js_findings);

    try stdout.print("\n── JavaScript: {d} findings (expected 1: SECRET only)\n", .{js_findings.len});

    try results.append(.{
        .name = "javascript_string_only",
        .passed = js_findings.len == 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1: SECRET)", .{js_findings.len}),
    });

    try printResults(stdout, results.items);
}

fn hasRuleAtRow(findings: []const matcher_mod.Finding, row_1based: u32) bool {
    for (findings) |f| {
        if (f.span.start_row + 1 == row_1based) return true;
    }
    return false;
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
    const verdict: []const u8 = if (fail_count == 0) "H12 CONFIRMED" else "H12 NEEDS WORK";
    writer.print("  Verdict: {s}\n\n", .{verdict}) catch return;
}
