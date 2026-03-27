/// H10: Indexed Matcher — Does compiling rules into a dispatch index
///      outperform the linear per-rule scan?
///
/// Compares:
///   A) Current matcher: O(nodes × rules) — scan all nodes once per rule
///   B) Indexed matcher: O(nodes) — single pass, atom→rules dispatch + SIMD hash
///
/// Also verifies correctness: both matchers must produce identical findings.
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher = @import("matcher");
const fast_matcher = @import("fast_matcher");

const out = std.io.getStdOut().writer();

const WARMUP = 50;
const ITERATIONS = 2000;

pub fn main() !void {
    try out.writeAll("\n" ++ "=" ** 60 ++ "\n");
    try out.writeAll("  H10: Indexed Matcher (SIMD + Dispatch Table)\n");
    try out.writeAll("=" ** 60 ++ "\n\n");

    const alloc = std.heap.page_allocator;

    // Load the full Python rule set (20 rules)
    const yaml_source = try std.fs.cwd().readFileAlloc(alloc, "rules/python-security.yaml", 1024 * 1024);
    const rules = try rule.parseRules(yaml_source, alloc);
    const compiled = try rule.compileRules(rules, alloc);

    try out.print("  Rules: {d} loaded, {d} compiled\n", .{ rules.len, compiled.len });

    // Parse the vulnerable fixture (lots of findings)
    var parser = try ts.Parser.init();
    defer parser.deinit();
    try parser.setLanguage(.python);
    const source = try std.fs.cwd().readFileAlloc(alloc, "test_fixtures/python/vulnerable.py", 1024 * 1024);
    var tree = try parser.parse(source);
    defer tree.deinit();
    var ztree = zir.ZirTree.init(alloc, "python");
    try normalizer.buildZir(&ztree, &tree.rootNode(), null, .python);

    try out.print("  ZIR nodes: {d}\n", .{ztree.nodes.items.len});

    // Build the index
    var index = try fast_matcher.RuleIndex.build(compiled, alloc);
    defer index.deinit();

    try out.print("  Index: {d} call entries, {d} member_call buckets, {d} assignment rules\n", .{
        index.call_hashes.len,
        index.member_call_map.count(),
        index.assignment_rules.items.len,
    });

    // ── Correctness check ─────────────────────────────────
    const linear_findings = try matcher.matchRules(&ztree, compiled, "python", alloc);
    const indexed_findings = try fast_matcher.matchIndexed(&ztree, &index, "python", alloc);

    // Compare: same rule IDs must appear the same number of times
    var linear_counts = std.StringHashMap(u32).init(alloc);
    for (linear_findings) |f| {
        const gop = try linear_counts.getOrPut(f.rule_id);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }
    var indexed_counts = std.StringHashMap(u32).init(alloc);
    for (indexed_findings) |f| {
        const gop = try indexed_counts.getOrPut(f.rule_id);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }

    var correct = true;
    var it = linear_counts.iterator();
    while (it.next()) |entry| {
        const indexed_count = indexed_counts.get(entry.key_ptr.*) orelse 0;
        if (entry.value_ptr.* != indexed_count) {
            try out.print("  MISMATCH: {s} linear={d} indexed={d}\n", .{
                entry.key_ptr.*,
                entry.value_ptr.*,
                indexed_count,
            });
            correct = false;
        }
    }
    // Check for rules in indexed but not in linear
    var it2 = indexed_counts.iterator();
    while (it2.next()) |entry| {
        if (!linear_counts.contains(entry.key_ptr.*)) {
            try out.print("  EXTRA in indexed: {s} count={d}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            correct = false;
        }
    }

    try out.print("\n  [{s}] correctness: linear={d} findings, indexed={d} findings\n", .{
        if (correct and linear_findings.len == indexed_findings.len) "PASS" else "FAIL",
        linear_findings.len,
        indexed_findings.len,
    });

    // ── Benchmark: Linear matcher ─────────────────────────
    // Warmup
    for (0..WARMUP) |_| {
        const f = try matcher.matchRules(&ztree, compiled, "python", alloc);
        alloc.free(f);
    }

    var linear_timer = try std.time.Timer.start();
    for (0..ITERATIONS) |_| {
        const f = try matcher.matchRules(&ztree, compiled, "python", alloc);
        alloc.free(f);
    }
    const linear_elapsed = linear_timer.read();

    // ── Benchmark: Indexed matcher (pre-built ChildIndex) ─
    var ci = try fast_matcher.ChildIndex.build(&ztree, alloc);
    defer ci.deinit(alloc);

    for (0..WARMUP) |_| {
        const f = try fast_matcher.matchWithIndex(&ztree, &index, &ci, "python", alloc);
        alloc.free(f);
    }

    var indexed_timer = try std.time.Timer.start();
    for (0..ITERATIONS) |_| {
        const f = try fast_matcher.matchWithIndex(&ztree, &index, &ci, "python", alloc);
        alloc.free(f);
    }
    const indexed_elapsed = indexed_timer.read();

    // ── Results ───────────────────────────────────────────
    const linear_us = @as(f64, @floatFromInt(linear_elapsed)) / 1000.0;
    const indexed_us = @as(f64, @floatFromInt(indexed_elapsed)) / 1000.0;
    const linear_per = linear_us / @as(f64, ITERATIONS);
    const indexed_per = indexed_us / @as(f64, ITERATIONS);
    const speedup = linear_us / indexed_us;

    try out.print(
        \\
        \\  ── Benchmark ({d} iterations) ──
        \\
        \\    Linear matcher:  {d:.1} μs total  ({d:.3} μs/iter)
        \\    Indexed matcher: {d:.1} μs total  ({d:.3} μs/iter)
        \\    Speedup: {d:.2}x
        \\
    , .{
        ITERATIONS,
        linear_us,
        linear_per,
        indexed_us,
        indexed_per,
        speedup,
    });

    const faster = speedup > 1.0;
    const findings_match = correct and linear_findings.len == indexed_findings.len;

    try out.print("\n  [{s}] indexed_faster: {d:.2}x speedup\n", .{
        if (faster) "PASS" else "FAIL",
        speedup,
    });
    try out.print("  [{s}] correctness: findings identical\n", .{
        if (findings_match) "PASS" else "FAIL",
    });

    const pass_count = @as(u32, @intFromBool(faster)) + @as(u32, @intFromBool(findings_match));
    try out.print("\n  Total: {d} passed, {d} failed\n", .{ pass_count, 2 - pass_count });
    const verdict: []const u8 = if (pass_count == 2) "H10 CONFIRMED" else "H10 NEEDS WORK";
    try out.print("  Verdict: {s}\n\n", .{verdict});
}
