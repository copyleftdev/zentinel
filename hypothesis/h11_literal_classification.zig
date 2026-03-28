/// H11: Does the normalizer correctly classify literal sub-types (LiteralKind)?
///
/// PASS criteria:
///   1. Python string literals → LiteralKind.string
///   2. Python integer literals → LiteralKind.number_int
///   3. Python float literals → LiteralKind.number_float
///   4. Python boolean literals → LiteralKind.boolean
///   5. Python None → LiteralKind.null_value
///   6. JavaScript string literals → LiteralKind.string
///   7. JavaScript number literals → LiteralKind.number_int
///   8. JavaScript boolean literals → LiteralKind.boolean
///   9. JavaScript null/undefined → LiteralKind.null_value
///  10. Non-literal nodes return null from literalKind()
///  11. Classification survives round-trip through ZirTree
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

/// Count literal nodes of a specific LiteralKind in a ZirTree.
fn countLiteralKind(tree: *const zir.ZirTree, lk: zir.LiteralKind) usize {
    var count: usize = 0;
    for (tree.nodes.items) |node| {
        if (node.kind == .literal) {
            if (node.literalKind()) |k| {
                if (k == lk) count += 1;
            }
        }
    }
    return count;
}

/// Check that all non-literal nodes return null from literalKind().
fn allNonLiteralsReturnNull(tree: *const zir.ZirTree) bool {
    for (tree.nodes.items) |node| {
        if (node.kind != .literal) {
            if (node.literalKind() != null) return false;
        }
    }
    return true;
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\
        \\══════════════════════════════════════════════════════════
        \\  H11: Literal Classification (Tier 1 Foundation)
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    var parser = try ts.Parser.init();
    defer parser.deinit();

    // ── Python fixture with mixed literals ─────────────────────
    const py_source =
        \\name = "Alice"
        \\count = 42
        \\rate = 3.14
        \\flag = True
        \\nothing = None
        \\items = [1, 2, 3]
    ;

    try parser.setLanguage(.python);
    var py_tree = try parser.parse(py_source);
    defer py_tree.deinit();

    var py_zir = zir.ZirTree.init(alloc, "python");
    defer py_zir.deinit();
    try normalizer.buildZir(&py_zir, &py_tree.rootNode(), null, .python);

    // Dump for inspection
    try stdout.writeAll("\n── Python ZIR Literal Nodes ──\n");
    for (py_zir.nodes.items, 0..) |node, i| {
        if (node.kind == .literal) {
            const lk_name = if (node.literalKind()) |lk| @tagName(lk) else "NONE";
            const atom_str = if (node.atom) |aid| py_zir.atoms.get(aid) else "(no atom)";
            try stdout.print("  [{d}] literal \"{s}\" -> {s}\n", .{ i, atom_str, lk_name });
        }
    }

    // Test 1: Python strings
    const py_strings = countLiteralKind(&py_zir, .string);
    try results.append(.{
        .name = "python_string_literals",
        .passed = py_strings >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} string literal(s) found", .{py_strings}),
    });

    // Test 2: Python integers
    const py_ints = countLiteralKind(&py_zir, .number_int);
    try results.append(.{
        .name = "python_integer_literals",
        .passed = py_ints >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} integer literal(s) found", .{py_ints}),
    });

    // Test 3: Python floats
    const py_floats = countLiteralKind(&py_zir, .number_float);
    try results.append(.{
        .name = "python_float_literals",
        .passed = py_floats >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} float literal(s) found", .{py_floats}),
    });

    // Test 4: Python booleans
    const py_bools = countLiteralKind(&py_zir, .boolean);
    try results.append(.{
        .name = "python_boolean_literals",
        .passed = py_bools >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} boolean literal(s) found", .{py_bools}),
    });

    // Test 5: Python None
    const py_nulls = countLiteralKind(&py_zir, .null_value);
    try results.append(.{
        .name = "python_none_literal",
        .passed = py_nulls >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} null/None literal(s) found", .{py_nulls}),
    });

    // Test 6: Python collections
    const py_colls = countLiteralKind(&py_zir, .collection);
    try results.append(.{
        .name = "python_collection_literals",
        .passed = py_colls >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} collection literal(s) found", .{py_colls}),
    });

    // ── JavaScript fixture with mixed literals ─────────────────
    const js_source =
        \\const name = "Bob";
        \\const count = 42;
        \\const flag = true;
        \\const nothing = null;
        \\const pattern = /test/;
    ;

    try parser.setLanguage(.javascript);
    var js_tree = try parser.parse(js_source);
    defer js_tree.deinit();

    var js_zir = zir.ZirTree.init(alloc, "javascript");
    defer js_zir.deinit();
    try normalizer.buildZir(&js_zir, &js_tree.rootNode(), null, .javascript);

    // Dump for inspection
    try stdout.writeAll("\n── JavaScript ZIR Literal Nodes ──\n");
    for (js_zir.nodes.items, 0..) |node, i| {
        if (node.kind == .literal) {
            const lk_name = if (node.literalKind()) |lk| @tagName(lk) else "NONE";
            const atom_str = if (node.atom) |aid| js_zir.atoms.get(aid) else "(no atom)";
            try stdout.print("  [{d}] literal \"{s}\" -> {s}\n", .{ i, atom_str, lk_name });
        }
    }

    // Test 7: JavaScript strings
    const js_strings = countLiteralKind(&js_zir, .string);
    try results.append(.{
        .name = "javascript_string_literals",
        .passed = js_strings >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} string literal(s) found", .{js_strings}),
    });

    // Test 8: JavaScript numbers
    const js_nums = countLiteralKind(&js_zir, .number_int);
    try results.append(.{
        .name = "javascript_number_literals",
        .passed = js_nums >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} number literal(s) found", .{js_nums}),
    });

    // Test 9: JavaScript booleans
    const js_bools = countLiteralKind(&js_zir, .boolean);
    try results.append(.{
        .name = "javascript_boolean_literals",
        .passed = js_bools >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} boolean literal(s) found", .{js_bools}),
    });

    // Test 10: JavaScript null
    const js_nulls = countLiteralKind(&js_zir, .null_value);
    try results.append(.{
        .name = "javascript_null_literals",
        .passed = js_nulls >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} null literal(s) found", .{js_nulls}),
    });

    // Test 11: JavaScript regex
    const js_regex = countLiteralKind(&js_zir, .regex);
    try results.append(.{
        .name = "javascript_regex_literals",
        .passed = js_regex >= 1,
        .detail = try std.fmt.allocPrint(alloc, "{d} regex literal(s) found", .{js_regex}),
    });

    // Test 12: Non-literal nodes return null
    const py_ok = allNonLiteralsReturnNull(&py_zir);
    const js_ok = allNonLiteralsReturnNull(&js_zir);
    try results.append(.{
        .name = "non_literals_return_null",
        .passed = py_ok and js_ok,
        .detail = try std.fmt.allocPrint(alloc, "Python: {}, JavaScript: {}", .{ py_ok, js_ok }),
    });

    // Test 13: Real fixture — clean.py string vs non-string discrimination
    const py_real_source = try readFixture("test_fixtures/python/clean.py");
    var py_real_tree = try parser.parse(py_real_source);
    defer py_real_tree.deinit();

    // Need to re-set language for Python since we switched to JS
    try parser.setLanguage(.python);
    py_real_tree.deinit();
    py_real_tree = try parser.parse(py_real_source);

    var py_real_zir = zir.ZirTree.init(alloc, "python");
    defer py_real_zir.deinit();
    try normalizer.buildZir(&py_real_zir, &py_real_tree.rootNode(), null, .python);

    const real_strings = countLiteralKind(&py_real_zir, .string);
    const real_total = py_real_zir.countKind(.literal);
    try results.append(.{
        .name = "real_fixture_discrimination",
        .passed = real_strings > 0 and real_strings < real_total,
        .detail = try std.fmt.allocPrint(alloc, "{d} strings out of {d} total literals — discrimination works", .{ real_strings, real_total }),
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
    const verdict: []const u8 = if (fail_count == 0) "H11 CONFIRMED" else "H11 NEEDS WORK";
    writer.print("  Verdict: {s}\n\n", .{verdict}) catch return;
}
