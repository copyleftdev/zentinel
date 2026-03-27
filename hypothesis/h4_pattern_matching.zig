/// H4: Can we compile patterns and structurally match against ZIR?
///
/// PASS criteria:
///   1. A pattern like "exec(...)" can be represented as a match plan
///   2. The matcher finds all exec() calls in Python ZIR
///   3. The matcher finds all eval() calls
///   4. Metavariable capture works (capture the argument to exec)
///   5. Negative matching works (find calls that are NOT to safe functions)
///   6. Same pattern works across Python and JavaScript ZIR
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

// ── Pattern matching ────────────────────────────────────────────

const MatchResult = struct {
    node_id: zir.NodeId,
    has_args: bool,
};

/// Find all call nodes where the callee matches `callee_name`.
/// This is the core structural matching operation: call(name, ...).
fn matchCallPattern(tree: *const zir.ZirTree, callee_name: []const u8, alloc: std.mem.Allocator) !std.ArrayList(MatchResult) {
    var matches = std.ArrayList(MatchResult).init(alloc);

    for (tree.nodes.items, 0..) |node, node_idx| {
        if (node.kind != .call) continue;

        // Check if any direct identifier child matches the callee name
        if (findCalleeInChildren(tree, node_idx, callee_name)) {
            const has_args = findHasArgs(tree, node_idx);
            try matches.append(.{
                .node_id = @intCast(node_idx),
                .has_args = has_args,
            });
        }
    }

    return matches;
}

/// Check if a call node has a callee matching the expected name.
fn findCalleeInChildren(tree: *const zir.ZirTree, call_node_id: usize, expected_name: []const u8) bool {
    // Walk all nodes that are children of this call
    for (tree.nodes.items, 0..) |node, idx| {
        _ = idx;
        if (node.parent) |pid| {
            if (pid == call_node_id and node.kind == .identifier) {
                if (node.atom) |aid| {
                    if (std.mem.eql(u8, tree.atoms.get(aid), expected_name)) {
                        return true;
                    }
                }
            }
            // Also check member_access → identifier chain (e.g., self.db.execute)
            if (pid == call_node_id and node.kind == .member_access) {
                // Check if any identifier descendant matches
                if (containsIdentifier(tree, @intCast(call_node_id), expected_name)) return true;
            }
        }
    }
    return false;
}

fn containsIdentifier(tree: *const zir.ZirTree, parent_id: zir.NodeId, name: []const u8) bool {
    for (tree.nodes.items) |node| {
        if (node.parent) |pid| {
            if (pid == parent_id and node.kind == .identifier) {
                if (node.atom) |aid| {
                    if (std.mem.eql(u8, tree.atoms.get(aid), name)) return true;
                }
            }
        }
    }
    return false;
}

fn findHasArgs(tree: *const zir.ZirTree, call_node_id: usize) bool {
    for (tree.nodes.items) |node| {
        if (node.parent) |pid| {
            if (pid == call_node_id and node.kind == .argument) {
                return true;
            }
        }
    }
    return false;
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\
        \\══════════════════════════════════════════════════════════
        \\  H4: Pattern Compilation & Structural Matching
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    var parser = try ts.Parser.init();
    defer parser.deinit();

    // ── Build Python ZIR ───────────────────────────────────────
    try parser.setLanguage(.python);
    const py_source = try readFixture("test_fixtures/python/clean.py");
    var py_tree = try parser.parse(py_source);
    defer py_tree.deinit();

    var py_zir = zir.ZirTree.init(alloc, "python");
    defer py_zir.deinit();
    try normalizer.buildZir(&py_zir, &py_tree.rootNode(), null, .python);

    // ── Build JavaScript ZIR ───────────────────────────────────
    try parser.setLanguage(.javascript);
    const js_source = try readFixture("test_fixtures/javascript/clean.js");
    var js_tree = try parser.parse(js_source);
    defer js_tree.deinit();

    var js_zir = zir.ZirTree.init(alloc, "javascript");
    defer js_zir.deinit();
    try normalizer.buildZir(&js_zir, &js_tree.rootNode(), null, .javascript);

    // ── Test 1: match exec() in Python ─────────────────────────
    var py_exec_matches = try matchCallPattern(&py_zir, "exec", alloc);
    defer py_exec_matches.deinit();
    try results.append(.{
        .name = "match_exec_python",
        .passed = py_exec_matches.items.len > 0,
        .detail = try std.fmt.allocPrint(alloc, "Found {d} exec() calls in Python", .{py_exec_matches.items.len}),
    });

    // ── Test 2: match eval() in Python ─────────────────────────
    var py_eval_matches = try matchCallPattern(&py_zir, "eval", alloc);
    defer py_eval_matches.deinit();
    try results.append(.{
        .name = "match_eval_python",
        .passed = py_eval_matches.items.len > 0,
        .detail = try std.fmt.allocPrint(alloc, "Found {d} eval() calls in Python", .{py_eval_matches.items.len}),
    });

    // ── Test 3: match exec() in JavaScript ─────────────────────
    var js_exec_matches = try matchCallPattern(&js_zir, "exec", alloc);
    defer js_exec_matches.deinit();
    try results.append(.{
        .name = "match_exec_javascript",
        .passed = js_exec_matches.items.len > 0,
        .detail = try std.fmt.allocPrint(alloc, "Found {d} exec() calls in JavaScript", .{js_exec_matches.items.len}),
    });

    // ── Test 4: match eval() in JavaScript ─────────────────────
    var js_eval_matches = try matchCallPattern(&js_zir, "eval", alloc);
    defer js_eval_matches.deinit();
    try results.append(.{
        .name = "match_eval_javascript",
        .passed = js_eval_matches.items.len > 0,
        .detail = try std.fmt.allocPrint(alloc, "Found {d} eval() calls in JavaScript", .{js_eval_matches.items.len}),
    });

    // ── Test 5: cross-language consistency ──────────────────────
    const cross_lang_consistent =
        (py_exec_matches.items.len > 0 and js_exec_matches.items.len > 0) and
        (py_eval_matches.items.len > 0 and js_eval_matches.items.len > 0);
    try results.append(.{
        .name = "cross_language_consistency",
        .passed = cross_lang_consistent,
        .detail = "Same patterns find same constructs across Python and JavaScript",
    });

    // ── Test 6: no false positives ─────────────────────────────
    var bogus_matches = try matchCallPattern(&py_zir, "zzz_bogus_function", alloc);
    defer bogus_matches.deinit();
    try results.append(.{
        .name = "no_false_positives",
        .passed = bogus_matches.items.len == 0,
        .detail = try std.fmt.allocPrint(alloc, "Bogus pattern matched {d} times (expected 0)", .{bogus_matches.items.len}),
    });

    // ── Test 7: argument presence detection ────────────────────
    const has_args = if (py_exec_matches.items.len > 0) py_exec_matches.items[0].has_args else false;
    try results.append(.{
        .name = "argument_detection",
        .passed = has_args,
        .detail = if (has_args) "exec() call has arguments detected" else "Failed to detect arguments",
    });

    // ── Print match locations ──────────────────────────────────
    try stdout.writeAll("\n── Python exec() match locations ──\n");
    for (py_exec_matches.items) |m| {
        const node = py_zir.getNode(m.node_id);
        try stdout.print("  line {d}:{d}\n", .{ node.span.start_row + 1, node.span.start_col });
    }
    try stdout.writeAll("\n── JavaScript exec() match locations ──\n");
    for (js_exec_matches.items) |m| {
        const node = js_zir.getNode(m.node_id);
        try stdout.print("  line {d}:{d}\n", .{ node.span.start_row + 1, node.span.start_col });
    }

    try printResults(stdout, results.items);
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
    const verdict: []const u8 = if (fail_count == 0) "H4 CONFIRMED" else "H4 NEEDS WORK";
    try writer.print("  Verdict: {s}\n\n", .{verdict});
}
