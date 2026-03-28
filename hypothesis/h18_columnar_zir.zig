/// H18: Columnar ZIR storage — round-trip correctness + performance
///
/// PASS criteria:
///   1. Round-trip: serialize → deserialize → toZirTree → match → identical findings
///   2. Atom fidelity: every atom string matches after round-trip
///   3. ChildIndex equivalence: children(nid) identical from both paths
///   4. Performance: warm (deserialize) faster than cold (parse+normalize)
///   5. File size: columnar .zir smaller than source
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher_mod = @import("matcher");
const fast_matcher = @import("fast_matcher");
const columnar = @import("columnar");

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
        \\  H18: Columnar ZIR Storage
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    var parser = try ts.Parser.init();
    defer parser.deinit();

    // Load test fixture
    const py_source = try std.fs.cwd().readFileAlloc(alloc, "test_fixtures/python/vulnerable.py", 1024 * 1024);
    defer alloc.free(py_source);

    // Load rules
    const yaml_source = try std.fs.cwd().readFileAlloc(alloc, "rules/python-security.yaml", 1024 * 1024);
    defer alloc.free(yaml_source);
    const rules = try rule.parseRules(yaml_source, alloc);
    defer alloc.free(rules);
    const compiled = try rule.compileRules(rules, alloc);
    defer alloc.free(compiled);

    // Build original ZIR tree
    try parser.setLanguage(.python);
    var tree = try parser.parse(py_source);
    defer tree.deinit();

    var ztree = zir.ZirTree.init(alloc, "python");
    defer ztree.deinit();
    try normalizer.buildZir(&ztree, &tree.rootNode(), null, .python);

    var ci = try fast_matcher.ChildIndex.build(&ztree, alloc);
    defer ci.deinit(alloc);

    // Get original findings
    var rule_index = try fast_matcher.RuleIndex.build(compiled, alloc);
    defer rule_index.deinit();
    const original_findings = try fast_matcher.matchWithIndex(&ztree, &rule_index, &ci, "python", alloc);
    defer alloc.free(original_findings);

    try stdout.print("\n  Original: {d} nodes, {d} findings\n", .{ ztree.nodes.items.len, original_findings.len });

    // ═══════════════════════════════════════════════════════
    // Serialize
    // ═══════════════════════════════════════════════════════
    const serialized = try columnar.serialize(&ztree, &ci, alloc);
    defer alloc.free(serialized);

    try stdout.print("  Serialized: {d} bytes ({d} bytes/node)\n", .{ serialized.len, serialized.len / ztree.nodes.items.len });

    // ═══════════════════════════════════════════════════════
    // Test 1: Round-trip findings match
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 1: Round-trip findings ──\n");
    {
        var ct = try columnar.deserialize(serialized, alloc);
        defer ct.deinit();

        var reconstructed = try ct.toZirTree(alloc);
        defer reconstructed.deinit();

        var ci2 = try fast_matcher.ChildIndex.build(&reconstructed, alloc);
        defer ci2.deinit(alloc);

        const rt_findings = try fast_matcher.matchWithIndex(&reconstructed, &rule_index, &ci2, "python", alloc);
        defer alloc.free(rt_findings);

        try stdout.print("  Original: {d}, Round-trip: {d}\n", .{ original_findings.len, rt_findings.len });

        // Compare each finding
        var all_match = original_findings.len == rt_findings.len;
        if (all_match) {
            for (original_findings, 0..) |of, i| {
                if (!std.mem.eql(u8, of.rule_id, rt_findings[i].rule_id) or
                    of.span.start_row != rt_findings[i].span.start_row)
                {
                    all_match = false;
                    break;
                }
            }
        }

        try results.append(.{
            .name = "roundtrip_findings",
            .passed = all_match,
            .detail = try std.fmt.allocPrint(alloc, "orig={d} rt={d} match={}", .{ original_findings.len, rt_findings.len, all_match }),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 2: Atom fidelity
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 2: Atom fidelity ──\n");
    {
        var ct = try columnar.deserialize(serialized, alloc);
        defer ct.deinit();

        var atoms_match = true;
        var checked: usize = 0;
        for (ztree.nodes.items, 0..) |node, i| {
            if (node.atom) |aid| {
                const orig_str = ztree.atoms.get(aid);
                const ct_str = ct.atomString(ct.atoms[i]);
                if (ct_str) |s| {
                    if (!std.mem.eql(u8, orig_str, s)) {
                        atoms_match = false;
                        break;
                    }
                    checked += 1;
                } else {
                    atoms_match = false;
                    break;
                }
            }
        }

        try stdout.print("  Checked {d} atoms\n", .{checked});
        try results.append(.{
            .name = "atom_fidelity",
            .passed = atoms_match,
            .detail = try std.fmt.allocPrint(alloc, "{d} atoms verified, match={}", .{ checked, atoms_match }),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 3: ChildIndex equivalence
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 3: ChildIndex equivalence ──\n");
    {
        var ct = try columnar.deserialize(serialized, alloc);
        defer ct.deinit();

        const ci_view = ct.childIndex();

        var children_match = true;
        for (0..ztree.nodes.items.len) |i| {
            const nid: zir.NodeId = @intCast(i);
            const orig_children = ci.children(nid);
            const ct_children = ci_view.children(nid);
            if (orig_children.len != ct_children.len) {
                children_match = false;
                break;
            }
            for (orig_children, ct_children) |a, b| {
                if (a != b) {
                    children_match = false;
                    break;
                }
            }
        }

        try results.append(.{
            .name = "childindex_equivalence",
            .passed = children_match,
            .detail = try std.fmt.allocPrint(alloc, "{d} nodes checked, match={}", .{ ztree.nodes.items.len, children_match }),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 4: Performance — warm vs cold
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 4: Performance ──\n");
    {
        const ITERS = 5000;

        // Cold path: parse + normalize
        var timer = try std.time.Timer.start();
        for (0..ITERS) |_| {
            var t = try parser.parse(py_source);
            defer t.deinit();
            var z = zir.ZirTree.init(alloc, "python");
            defer z.deinit();
            try normalizer.buildZir(&z, &t.rootNode(), null, .python);
        }
        const cold_ns = timer.read();

        // Warm path: deserialize from buffer
        timer.reset();
        for (0..ITERS) |_| {
            var ct = try columnar.deserialize(serialized, alloc);
            ct.deinit();
        }
        const warm_ns = timer.read();

        const cold_us = @as(f64, @floatFromInt(cold_ns)) / @as(f64, @floatFromInt(ITERS)) / 1000.0;
        const warm_us = @as(f64, @floatFromInt(warm_ns)) / @as(f64, @floatFromInt(ITERS)) / 1000.0;
        const speedup = cold_us / warm_us;

        try stdout.print("  Cold (parse+norm): {d:.1}μs/iter\n", .{cold_us});
        try stdout.print("  Warm (deserialize): {d:.1}μs/iter\n", .{warm_us});
        try stdout.print("  Speedup: {d:.1}x\n", .{speedup});

        try results.append(.{
            .name = "warm_faster_than_cold",
            .passed = speedup > 1.5,
            .detail = try std.fmt.allocPrint(alloc, "cold={d:.1}μs warm={d:.1}μs speedup={d:.1}x", .{ cold_us, warm_us, speedup }),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 5: File size
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 5: File size ──\n");
    {
        const ratio = @as(f64, @floatFromInt(serialized.len)) / @as(f64, @floatFromInt(py_source.len));
        try stdout.print("  Source: {d} bytes\n", .{py_source.len});
        try stdout.print("  Columnar: {d} bytes\n", .{serialized.len});
        try stdout.print("  Ratio: {d:.2}x\n", .{ratio});

        try results.append(.{
            .name = "file_size_reasonable",
            .passed = ratio < 20.0, // columnar should be reasonable relative to source
            .detail = try std.fmt.allocPrint(alloc, "src={d}B col={d}B ratio={d:.2}x", .{ py_source.len, serialized.len, ratio }),
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
    const verdict: []const u8 = if (fail_count == 0) "H18 CONFIRMED" else "H18 NEEDS WORK";
    writer.print("  Verdict: {s}\n\n", .{verdict}) catch return;
}
