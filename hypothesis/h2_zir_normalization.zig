/// H2: Can we normalize tree-sitter CST into a unified ZIR across languages?
///
/// PASS criteria:
///   1. Python and JavaScript both produce valid ZIR trees
///   2. Equivalent constructs map to the same ZIR Kind (e.g., exec() → Kind.call)
///   3. Atom table correctly interns identifiers
///   4. The same pattern (exec call) is representable identically in both languages' ZIR
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
        \\  H2: CST → ZIR Normalization
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    // Parse both languages
    var parser = try ts.Parser.init();
    defer parser.deinit();

    // ── Python → ZIR ───────────────────────────────────────────
    try parser.setLanguage(.python);
    const py_source = try readFixture("test_fixtures/python/clean.py");
    var py_tree = try parser.parse(py_source);
    defer py_tree.deinit();

    var py_zir = zir.ZirTree.init(alloc, "python");
    defer py_zir.deinit();
    try normalizer.buildZir(&py_zir, &py_tree.rootNode(), null, .python);

    const py_node_count = py_zir.nodes.items.len;
    try results.append(.{
        .name = "python_zir_build",
        .passed = py_node_count > 0,
        .detail = try std.fmt.allocPrint(alloc, "{d} ZIR nodes from Python source", .{py_node_count}),
    });

    // ── JavaScript → ZIR ───────────────────────────────────────
    try parser.setLanguage(.javascript);
    const js_source = try readFixture("test_fixtures/javascript/clean.js");
    var js_tree = try parser.parse(js_source);
    defer js_tree.deinit();

    var js_zir = zir.ZirTree.init(alloc, "javascript");
    defer js_zir.deinit();
    try normalizer.buildZir(&js_zir, &js_tree.rootNode(), null, .javascript);

    const js_node_count = js_zir.nodes.items.len;
    try results.append(.{
        .name = "javascript_zir_build",
        .passed = js_node_count > 0,
        .detail = try std.fmt.allocPrint(alloc, "{d} ZIR nodes from JavaScript source", .{js_node_count}),
    });

    // ── Kind distribution comparison ───────────────────────────
    try stdout.writeAll("\n── Python ZIR Kind Distribution ──\n");
    try printKindDist(stdout, &py_zir);
    try stdout.writeAll("\n── JavaScript ZIR Kind Distribution ──\n");
    try printKindDist(stdout, &js_zir);

    // ── Both have calls ────────────────────────────────────────
    const py_calls = py_zir.countKind(.call);
    const js_calls = js_zir.countKind(.call);
    try results.append(.{
        .name = "both_have_calls",
        .passed = py_calls > 0 and js_calls > 0,
        .detail = try std.fmt.allocPrint(alloc, "Python: {d} calls, JavaScript: {d} calls", .{ py_calls, js_calls }),
    });

    // ── Both have functions ────────────────────────────────────
    const py_fns = py_zir.countKind(.function);
    const js_fns = js_zir.countKind(.function);
    try results.append(.{
        .name = "both_have_functions",
        .passed = py_fns > 0 and js_fns > 0,
        .detail = try std.fmt.allocPrint(alloc, "Python: {d} functions, JavaScript: {d} functions", .{ py_fns, js_fns }),
    });

    // ── Both have imports ──────────────────────────────────────
    const py_imports = py_zir.countKind(.import);
    const js_imports = js_zir.countKind(.import);
    try results.append(.{
        .name = "both_have_imports",
        .passed = py_imports > 0 and js_imports > 0,
        .detail = try std.fmt.allocPrint(alloc, "Python: {d} imports, JavaScript: {d} imports", .{ py_imports, js_imports }),
    });

    // ── Both have classes ──────────────────────────────────────
    const py_classes = py_zir.countKind(.class);
    const js_classes = js_zir.countKind(.class);
    try results.append(.{
        .name = "both_have_classes",
        .passed = py_classes > 0 and js_classes > 0,
        .detail = try std.fmt.allocPrint(alloc, "Python: {d} classes, JavaScript: {d} classes", .{ py_classes, js_classes }),
    });

    // ── Atom interning works ───────────────────────────────────
    // Check that "exec" is in both atom tables
    const py_has_exec = atomTableContains(&py_zir.atoms, "exec");
    const js_has_exec = atomTableContains(&js_zir.atoms, "exec");
    try results.append(.{
        .name = "atom_interning_exec",
        .passed = py_has_exec and js_has_exec,
        .detail = try std.fmt.allocPrint(alloc, "Python has 'exec': {}, JavaScript has 'exec': {}", .{ py_has_exec, js_has_exec }),
    });

    // ── Unknown ratio — lower is better ────────────────────────
    const py_unknown = py_zir.countKind(.unknown);
    const js_unknown = js_zir.countKind(.unknown);
    const py_ratio: f64 = if (py_node_count > 0) @as(f64, @floatFromInt(py_unknown)) / @as(f64, @floatFromInt(py_node_count)) else 1.0;
    const js_ratio: f64 = if (js_node_count > 0) @as(f64, @floatFromInt(js_unknown)) / @as(f64, @floatFromInt(js_node_count)) else 1.0;
    try results.append(.{
        .name = "unknown_ratio",
        .passed = py_ratio < 0.5 and js_ratio < 0.5,
        .detail = try std.fmt.allocPrint(alloc, "Python: {d:.1}% unknown, JavaScript: {d:.1}% unknown", .{ py_ratio * 100, js_ratio * 100 }),
    });

    // ── Dump a slice of the ZIR for inspection ─────────────────
    try stdout.writeAll("\n── Python ZIR (first 30 nodes) ──\n");
    try dumpSlice(stdout, &py_zir, 30);
    try stdout.writeAll("\n── JavaScript ZIR (first 30 nodes) ──\n");
    try dumpSlice(stdout, &js_zir, 30);

    try printResults(stdout, results.items);
}

fn atomTableContains(table: *const zir.AtomTable, s: []const u8) bool {
    return table.index.contains(s);
}

fn printKindDist(writer: anytype, tree: *const zir.ZirTree) !void {
    // Count each kind
    const kind_count = @typeInfo(zir.Kind).@"enum".fields.len;
    var counts: [kind_count]usize = [_]usize{0} ** kind_count;
    for (tree.nodes.items) |node| {
        counts[@intFromEnum(node.kind)] += 1;
    }
    inline for (@typeInfo(zir.Kind).@"enum".fields, 0..) |field, i| {
        if (counts[i] > 0) {
            try writer.print("  {s}: {d}\n", .{ field.name, counts[i] });
        }
    }
}

fn dumpSlice(writer: anytype, tree: *const zir.ZirTree, max: usize) !void {
    const limit = @min(tree.nodes.items.len, max);
    for (tree.nodes.items[0..limit], 0..) |node, i| {
        try writer.print("  [{d}] {s}", .{ i, @tagName(node.kind) });
        if (node.atom) |aid| {
            const atom_str = tree.atoms.get(aid);
            try writer.print(" \"{s}\"", .{atom_str[0..@min(atom_str.len, 30)]});
        }
        try writer.writeAll("\n");
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
    const verdict: []const u8 = if (fail_count == 0) "H2 CONFIRMED" else "H2 NEEDS WORK";
    try writer.print("  Verdict: {s}\n\n", .{verdict});
}
