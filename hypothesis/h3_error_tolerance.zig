/// H3: Does tree-sitter produce usable structure from broken code?
///
/// PASS criteria:
///   1. Parsing broken code does NOT return null (tree-sitter should always produce a tree)
///   2. The tree contains ERROR nodes but also valid structure around them
///   3. We can still extract ZIR nodes (calls, identifiers) from broken code
///   4. Quantify: what % of structure survives breakage?
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");

fn readFixture(path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(std.heap.page_allocator, 1024 * 1024);
}

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
        \\  H3: Error-Tolerant Parsing → Usable ZIR
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    var parser = try ts.Parser.init();
    defer parser.deinit();

    // ── Python: clean vs broken ────────────────────────────────
    try parser.setLanguage(.python);
    const py_clean = try readFixture("test_fixtures/python/clean.py");
    const py_broken = try readFixture("test_fixtures/python/broken.py");

    var py_clean_tree = try parser.parse(py_clean);
    defer py_clean_tree.deinit();
    var py_broken_tree = try parser.parse(py_broken);
    defer py_broken_tree.deinit();

    // Test: broken code still produces a tree
    try results.append(.{
        .name = "py_broken_parses",
        .passed = true, // if we got here, it parsed
        .detail = "tree-sitter produced a tree from broken Python",
    });

    // Count structure in both
    const py_clean_stats = countStructure(&py_clean_tree.rootNode());
    const py_broken_stats = countStructure(&py_broken_tree.rootNode());

    try stdout.print("\n── Python Clean: {d} named, {d} errors\n", .{ py_clean_stats.named, py_clean_stats.errors });
    try stdout.print("── Python Broken: {d} named, {d} errors\n", .{ py_broken_stats.named, py_broken_stats.errors });

    // Broken should have some errors
    try results.append(.{
        .name = "py_broken_has_errors",
        .passed = py_broken_stats.errors > 0,
        .detail = try std.fmt.allocPrint(alloc, "{d} ERROR nodes detected in broken Python", .{py_broken_stats.errors}),
    });

    // Broken should still have useful structure
    const py_survival = if (py_clean_stats.named > 0)
        @as(f64, @floatFromInt(py_broken_stats.named)) / @as(f64, @floatFromInt(py_clean_stats.named)) * 100.0
    else
        0.0;
    try results.append(.{
        .name = "py_structure_survival",
        .passed = py_survival > 30.0,
        .detail = try std.fmt.allocPrint(alloc, "{d:.1}% of named nodes survived ({d}/{d})", .{ py_survival, py_broken_stats.named, py_clean_stats.named }),
    });

    // Build ZIR from broken code — can we still find calls?
    var py_broken_zir = zir.ZirTree.init(alloc, "python");
    defer py_broken_zir.deinit();
    try normalizer.buildZirErrorTolerant(&py_broken_zir, &py_broken_tree.rootNode(), null, .python);

    const py_broken_calls = py_broken_zir.countKind(.call);
    const py_broken_ids = py_broken_zir.countKind(.identifier);
    try results.append(.{
        .name = "py_broken_zir_calls",
        .passed = py_broken_calls > 0,
        .detail = try std.fmt.allocPrint(alloc, "Found {d} calls and {d} identifiers in broken Python ZIR", .{ py_broken_calls, py_broken_ids }),
    });

    // Check specifically for exec — it's in the broken code
    const has_exec = blk: {
        for (py_broken_zir.nodes.items) |node| {
            if (node.kind == .identifier) {
                if (node.atom) |aid| {
                    if (std.mem.eql(u8, py_broken_zir.atoms.get(aid), "exec")) break :blk true;
                }
            }
        }
        break :blk false;
    };
    try results.append(.{
        .name = "py_broken_finds_exec",
        .passed = has_exec,
        .detail = if (has_exec) "Found 'exec' identifier in broken code ZIR" else "Could not find 'exec' in broken code",
    });

    // ── JavaScript: clean vs broken ────────────────────────────
    try parser.setLanguage(.javascript);
    const js_clean = try readFixture("test_fixtures/javascript/clean.js");
    const js_broken = try readFixture("test_fixtures/javascript/broken.js");

    var js_clean_tree = try parser.parse(js_clean);
    defer js_clean_tree.deinit();
    var js_broken_tree = try parser.parse(js_broken);
    defer js_broken_tree.deinit();

    const js_clean_stats = countStructure(&js_clean_tree.rootNode());
    const js_broken_stats = countStructure(&js_broken_tree.rootNode());

    try stdout.print("── JavaScript Clean: {d} named, {d} errors\n", .{ js_clean_stats.named, js_clean_stats.errors });
    try stdout.print("── JavaScript Broken: {d} named, {d} errors\n", .{ js_broken_stats.named, js_broken_stats.errors });

    const js_survival = if (js_clean_stats.named > 0)
        @as(f64, @floatFromInt(js_broken_stats.named)) / @as(f64, @floatFromInt(js_clean_stats.named)) * 100.0
    else
        0.0;
    try results.append(.{
        .name = "js_structure_survival",
        .passed = js_survival > 30.0,
        .detail = try std.fmt.allocPrint(alloc, "{d:.1}% of named nodes survived ({d}/{d})", .{ js_survival, js_broken_stats.named, js_clean_stats.named }),
    });

    var js_broken_zir = zir.ZirTree.init(alloc, "javascript");
    defer js_broken_zir.deinit();
    try normalizer.buildZirErrorTolerant(&js_broken_zir, &js_broken_tree.rootNode(), null, .javascript);

    const js_broken_calls = js_broken_zir.countKind(.call);
    try results.append(.{
        .name = "js_broken_zir_calls",
        .passed = js_broken_calls > 0,
        .detail = try std.fmt.allocPrint(alloc, "Found {d} calls in broken JavaScript ZIR", .{js_broken_calls}),
    });

    // ── Print results ──────────────────────────────────────────
    try printResults(stdout, results.items);
}

const Stats = struct { named: u32, errors: u32, total: u32, missing: u32 };

fn countStructure(node: *const ts.Node) Stats {
    var stats = Stats{ .named = 0, .errors = 0, .total = 0, .missing = 0 };
    countStructureInner(node, &stats);
    return stats;
}

fn countStructureInner(node: *const ts.Node, stats: *Stats) void {
    stats.total += 1;
    if (node.isNamed()) stats.named += 1;
    if (std.mem.eql(u8, node.nodeType(), "ERROR")) stats.errors += 1;
    if (node.isMissing()) stats.missing += 1;
    var i: u32 = 0;
    while (i < node.childCount()) : (i += 1) {
        if (node.child(i)) |ch| {
            countStructureInner(&ch, stats);
        }
    }
}

fn printResults(writer: anytype, results_list: []const Result) !void {
    try writer.writeAll("\n── Results ─────────────────────────────────────────────\n");
    var pass_count: u32 = 0;
    var fail_count: u32 = 0;
    for (results_list) |r| {
        const icon: []const u8 = if (r.passed) "PASS" else "FAIL";
        try writer.print("  [{s}] {s}: {s}\n", .{ icon, r.name, r.detail });
        if (r.passed) pass_count += 1 else fail_count += 1;
    }
    try writer.print("\n  Total: {d} passed, {d} failed\n", .{ pass_count, fail_count });
    const verdict: []const u8 = if (fail_count == 0) "H3 CONFIRMED" else "H3 NEEDS WORK";
    try writer.print("  Verdict: {s}\n\n", .{verdict});
}
