/// H1: Can Zig call tree-sitter's C API to parse and walk a CST?
///
/// PASS criteria:
///   1. Parser creation succeeds
///   2. Language assignment succeeds (Python + JavaScript)
///   3. Parsing returns a valid tree
///   4. Tree walking visits all expected node types
///   5. Span (byte offset) fidelity: node text matches source slice
///
const std = @import("std");
const ts = @import("treesitter");

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
        \\  H1: Tree-sitter FFI from Zig
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();

    // ── Test 1: Parser creation ────────────────────────────────
    var parser = ts.Parser.init() catch {
        try results.append(.{ .name = "parser_creation", .passed = false, .detail = "ts_parser_new() returned null" });
        try printResults(stdout, results.items);
        return;
    };
    defer parser.deinit();
    try results.append(.{ .name = "parser_creation", .passed = true, .detail = "ts_parser_new() succeeded" });

    // ── Test 2: Language assignment ────────────────────────────
    for ([_]struct { lang: ts.Language, name: []const u8 }{
        .{ .lang = .python, .name = "python" },
        .{ .lang = .javascript, .name = "javascript" },
    }) |entry| {
        parser.setLanguage(entry.lang) catch {
            try results.append(.{
                .name = try std.fmt.allocPrint(std.heap.page_allocator, "set_language_{s}", .{entry.name}),
                .passed = false,
                .detail = "version mismatch or ABI incompatible",
            });
            continue;
        };
        try results.append(.{
            .name = try std.fmt.allocPrint(std.heap.page_allocator, "set_language_{s}", .{entry.name}),
            .passed = true,
            .detail = "language set successfully",
        });
    }

    // ── Test 3: Parse Python source ────────────────────────────
    const py_source = try readFixture("test_fixtures/python/clean.py");
    parser.setLanguage(.python) catch unreachable;
    var py_tree = parser.parse(py_source) catch {
        try results.append(.{ .name = "parse_python", .passed = false, .detail = "parse returned null" });
        try printResults(stdout, results.items);
        return;
    };
    defer py_tree.deinit();

    const py_root = py_tree.rootNode();
    const py_child_count = py_root.childCount();
    try results.append(.{
        .name = "parse_python",
        .passed = py_child_count > 0,
        .detail = try std.fmt.allocPrint(std.heap.page_allocator, "root has {d} children, type=\"{s}\"", .{ py_child_count, py_root.nodeType() }),
    });

    // ── Test 4: Parse JavaScript source ────────────────────────
    const js_source = try readFixture("test_fixtures/javascript/clean.js");
    parser.setLanguage(.javascript) catch unreachable;
    var js_tree = parser.parse(js_source) catch {
        try results.append(.{ .name = "parse_javascript", .passed = false, .detail = "parse returned null" });
        try printResults(stdout, results.items);
        return;
    };
    defer js_tree.deinit();

    const js_root = js_tree.rootNode();
    const js_child_count = js_root.childCount();
    try results.append(.{
        .name = "parse_javascript",
        .passed = js_child_count > 0,
        .detail = try std.fmt.allocPrint(std.heap.page_allocator, "root has {d} children, type=\"{s}\"", .{ js_child_count, js_root.nodeType() }),
    });

    // ── Test 5: Tree walking — count named nodes ───────────────
    var py_named_count: u32 = 0;
    var py_total_count: u32 = 0;
    countNodes(&py_root, &py_named_count, &py_total_count);
    try results.append(.{
        .name = "walk_python_tree",
        .passed = py_named_count > 10,
        .detail = try std.fmt.allocPrint(std.heap.page_allocator, "{d} named nodes, {d} total nodes", .{ py_named_count, py_total_count }),
    });

    var js_named_count: u32 = 0;
    var js_total_count: u32 = 0;
    countNodes(&js_root, &js_named_count, &js_total_count);
    try results.append(.{
        .name = "walk_javascript_tree",
        .passed = js_named_count > 10,
        .detail = try std.fmt.allocPrint(std.heap.page_allocator, "{d} named nodes, {d} total nodes", .{ js_named_count, js_total_count }),
    });

    // ── Test 6: Span fidelity — verify byte offsets ────────────
    // Find the first function_definition in Python and check its text
    const fn_node = findFirstNamed(&py_root, "function_definition");
    if (fn_node) |fnode| {
        const node_text = fnode.text();
        const starts_correctly = std.mem.startsWith(u8, node_text, "def ");
        try results.append(.{
            .name = "span_fidelity",
            .passed = starts_correctly,
            .detail = try std.fmt.allocPrint(std.heap.page_allocator, "function text starts with: \"{s}\"", .{node_text[0..@min(node_text.len, 40)]}),
        });
    } else {
        try results.append(.{ .name = "span_fidelity", .passed = false, .detail = "could not find function_definition node" });
    }

    // ── Test 7: Cursor-based traversal works ───────────────────
    var cursor = ts.Cursor.init(py_root);
    defer cursor.deinit();
    var cursor_count: u32 = 0;
    countWithCursor(&cursor, &cursor_count);
    try results.append(.{
        .name = "cursor_traversal",
        .passed = cursor_count == py_total_count,
        .detail = try std.fmt.allocPrint(std.heap.page_allocator, "cursor visited {d} nodes (expected {d})", .{ cursor_count, py_total_count }),
    });

    // ── Print results ──────────────────────────────────────────
    try printResults(stdout, results.items);
}

fn countNodes(node: *const ts.Node, named: *u32, total: *u32) void {
    total.* += 1;
    if (node.isNamed()) named.* += 1;
    var i: u32 = 0;
    while (i < node.childCount()) : (i += 1) {
        if (node.child(i)) |ch| {
            countNodes(&ch, named, total);
        }
    }
}

fn findFirstNamed(node: *const ts.Node, target_type: []const u8) ?ts.Node {
    if (node.isNamed() and std.mem.eql(u8, node.nodeType(), target_type)) {
        return node.*;
    }
    var i: u32 = 0;
    while (i < node.childCount()) : (i += 1) {
        if (node.child(i)) |ch| {
            if (findFirstNamed(&ch, target_type)) |found| return found;
        }
    }
    return null;
}

fn countWithCursor(cursor: *ts.Cursor, count: *u32) void {
    count.* += 1;
    if (cursor.gotoFirstChild()) {
        countWithCursor(cursor, count);
        while (cursor.gotoNextSibling()) {
            countWithCursor(cursor, count);
        }
        _ = cursor.gotoParent();
    }
}

fn printResults(writer: anytype, results: []const Result) !void {
    try writer.writeAll("\n── Results ─────────────────────────────────────────────\n");
    var pass_count: u32 = 0;
    var fail_count: u32 = 0;
    for (results) |r| {
        const icon: []const u8 = if (r.passed) "PASS" else "FAIL";
        try writer.print("  [{s}] {s}: {s}\n", .{ icon, r.name, r.detail });
        if (r.passed) pass_count += 1 else fail_count += 1;
    }
    try writer.print("\n  Total: {d} passed, {d} failed\n", .{ pass_count, fail_count });
    const verdict: []const u8 = if (fail_count == 0) "H1 CONFIRMED" else "H1 NEEDS WORK";
    try writer.print("  Verdict: {s}\n\n", .{verdict});
}
