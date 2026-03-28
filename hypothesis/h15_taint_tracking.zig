/// H15: Intra-procedural taint tracking (Tier 2)
///
/// PASS criteria:
///   1. Direct param→sink: exec(user_input) — 1 finding
///   2. One-hop: cmd = user_input; exec(cmd) — 1 finding
///   3. Multi-hop: a = user_input; b = a; exec(b) — 1 finding
///   4. F-string propagation: q = f"...{user_id}..."; cursor.execute(q) — 1 finding
///   5. Call propagation: result = func(tainted); exec(result) — 1 finding
///   6. Safe variable: safe = "constant"; exec(safe) — 0 Tier 2 findings
///   7. Cross-language (JavaScript): same pattern works — 1 finding
///   8. Performance: Tier 2 within bounds
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher_mod = @import("matcher");
const fast_matcher = @import("fast_matcher");
const taint = @import("taint");

const Result = struct {
    name: []const u8,
    passed: bool,
    detail: []const u8,
};

fn runTaintTest(
    parser: *ts.Parser,
    source: []const u8,
    lang: ts.Language,
    lang_name: []const u8,
    sinks: []const taint.SinkSpec,
    alloc: std.mem.Allocator,
) ![]matcher_mod.Finding {
    try parser.setLanguage(lang);
    var tree = try parser.parse(source);
    defer tree.deinit();

    var ztree = zir.ZirTree.init(alloc, lang_name);
    defer ztree.deinit();
    try normalizer.buildZir(&ztree, &tree.rootNode(), null, lang);

    var ci = try fast_matcher.ChildIndex.build(&ztree, alloc);
    defer ci.deinit(alloc);

    return taint.analyzeTaint(&ztree, &ci, sinks, lang_name, alloc);
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\
        \\══════════════════════════════════════════════════════════
        \\  H15: Taint Tracking (Tier 2)
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    var parser = try ts.Parser.init();
    defer parser.deinit();

    const exec_sink = [_]taint.SinkSpec{.{
        .rule_id = "tainted-exec",
        .message = "tainted data flows to exec()",
        .severity = .ERROR,
        .callee = "exec",
        .object = null,
        .method = null,
    }};

    // ═══════════════════════════════════════════════════════
    // Test 1: Direct param→sink
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 1: Direct param→sink ──\n");
    {
        const src =
            \\def f(user_input):
            \\    exec(user_input)
        ;
        const findings = try runTaintTest(&parser, src, .python, "python", &exec_sink, alloc);
        defer alloc.free(findings);
        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
        try results.append(.{
            .name = "direct_param_to_sink",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 2: One-hop assignment propagation
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 2: One-hop assignment ──\n");
    {
        const src =
            \\def process(user_input):
            \\    cmd = user_input
            \\    exec(cmd)
        ;
        const findings = try runTaintTest(&parser, src, .python, "python", &exec_sink, alloc);
        defer alloc.free(findings);
        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
        try results.append(.{
            .name = "one_hop_assignment",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 3: Multi-hop propagation
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 3: Multi-hop propagation ──\n");
    {
        const src =
            \\def process(user_input):
            \\    a = user_input
            \\    b = a
            \\    exec(b)
        ;
        const findings = try runTaintTest(&parser, src, .python, "python", &exec_sink, alloc);
        defer alloc.free(findings);
        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
        try results.append(.{
            .name = "multi_hop_propagation",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 4: F-string propagation
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 4: F-string propagation ──\n");
    {
        const cursor_sink = [_]taint.SinkSpec{.{
            .rule_id = "tainted-execute",
            .message = "tainted data flows to cursor.execute()",
            .severity = .ERROR,
            .callee = null,
            .object = "cursor",
            .method = "execute",
        }};
        const src =
            \\def query(cursor, user_id):
            \\    q = f"SELECT * FROM users WHERE id = {user_id}"
            \\    cursor.execute(q)
        ;
        const findings = try runTaintTest(&parser, src, .python, "python", &cursor_sink, alloc);
        defer alloc.free(findings);
        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
        try results.append(.{
            .name = "fstring_propagation",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 5: Call propagation (conservative)
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 5: Call propagation ──\n");
    {
        const src =
            \\def process(user_input):
            \\    result = some_func(user_input)
            \\    exec(result)
        ;
        const findings = try runTaintTest(&parser, src, .python, "python", &exec_sink, alloc);
        defer alloc.free(findings);
        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
        try results.append(.{
            .name = "call_propagation",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 6: Safe variable (no taint)
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 6: Safe variable ──\n");
    {
        const src =
            \\def process(user_input):
            \\    safe = "constant"
            \\    exec(safe)
        ;
        const findings = try runTaintTest(&parser, src, .python, "python", &exec_sink, alloc);
        defer alloc.free(findings);
        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
        try results.append(.{
            .name = "safe_variable",
            .passed = findings.len == 0,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 0)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 7: Cross-language (JavaScript)
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 7: JavaScript cross-language ──\n");
    {
        const eval_sink = [_]taint.SinkSpec{.{
            .rule_id = "tainted-eval",
            .message = "tainted data flows to eval()",
            .severity = .ERROR,
            .callee = "eval",
            .object = null,
            .method = null,
        }};
        const src =
            \\function process(userInput) {
            \\    const cmd = userInput;
            \\    eval(cmd);
            \\}
        ;
        const findings = try runTaintTest(&parser, src, .javascript, "javascript", &eval_sink, alloc);
        defer alloc.free(findings);
        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });
        try results.append(.{
            .name = "javascript_cross_language",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 8: Performance
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 8: Performance ──\n");
    {
        const py_source = try std.fs.cwd().readFileAlloc(alloc, "test_fixtures/python/clean.py", 1024 * 1024);
        defer alloc.free(py_source);

        try parser.setLanguage(.python);
        var tree = try parser.parse(py_source);
        defer tree.deinit();
        var ztree = zir.ZirTree.init(alloc, "python");
        defer ztree.deinit();
        try normalizer.buildZir(&ztree, &tree.rootNode(), null, .python);

        var ci = try fast_matcher.ChildIndex.build(&ztree, alloc);
        defer ci.deinit(alloc);

        const ITERS = 10_000;
        var timer = try std.time.Timer.start();
        for (0..ITERS) |_| {
            const f = try taint.analyzeTaint(&ztree, &ci, &exec_sink, "python", alloc);
            alloc.free(f);
        }
        const taint_ns = timer.read();
        const per_iter_us = @as(f64, @floatFromInt(taint_ns)) / @as(f64, @floatFromInt(ITERS)) / 1000.0;
        try stdout.print("  {d:.1}μs per taint analysis ({d} iters)\n", .{ per_iter_us, ITERS });

        try results.append(.{
            .name = "performance",
            .passed = per_iter_us < 5000.0, // < 5ms per file
            .detail = try std.fmt.allocPrint(alloc, "{d:.1}μs per analysis (target < 5000μs)", .{per_iter_us}),
        });
    }

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
    const verdict: []const u8 = if (fail_count == 0) "H15 CONFIRMED" else "H15 NEEDS WORK";
    writer.print("  Verdict: {s}\n\n", .{verdict}) catch return;
}
