/// H17: Custom taint sources/sinks configuration
///
/// PASS criteria:
///   1. Custom source (request.args.get) → tainted → sink → finding
///   2. No custom source match → no taint → no finding
///   3. Custom source + assignment chain → finding propagates
///   4. Params-only (no custom sources) still works → backward compat
///   5. Multiple sources → any match taints
///   6. YAML parsing of sources: field works end-to-end
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

fn runTaintWithSinks(
    parser: *ts.Parser,
    source: []const u8,
    sinks: []const taint.SinkSpec,
    alloc: std.mem.Allocator,
) ![]matcher_mod.Finding {
    try parser.setLanguage(.python);
    var tree = try parser.parse(source);
    defer tree.deinit();

    var ztree = zir.ZirTree.init(alloc, "python");
    defer ztree.deinit();
    try normalizer.buildZir(&ztree, &tree.rootNode(), null, .python);

    var ci = try fast_matcher.ChildIndex.build(&ztree, alloc);
    defer ci.deinit(alloc);

    return taint.analyzeTaint(&ztree, &ci, sinks, "python", alloc);
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\
        \\══════════════════════════════════════════════════════════
        \\  H17: Custom Taint Sources/Sinks
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    var parser = try ts.Parser.init();
    defer parser.deinit();

    // ═══════════════════════════════════════════════════════
    // Test 1: Custom source → tainted → sink
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 1: Custom source → sink ──\n");
    {
        const request_source = taint.parseSourcePattern("request.get(...)");
        const sinks = [_]taint.SinkSpec{.{
            .rule_id = "sql-injection",
            .message = "SQL injection via request data",
            .severity = .ERROR,
            .callee = null,
            .object = "cursor",
            .method = "execute",
            .sources = &[_]taint.SourceSpec{request_source},
        }};
        const src =
            \\def handle():
            \\    user_id = request.get("id")
            \\    query = f"SELECT * FROM users WHERE id = {user_id}"
            \\    cursor.execute(query)
        ;
        const findings = try runTaintWithSinks(&parser, src, &sinks, alloc);
        defer alloc.free(findings);
        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });

        try results.append(.{
            .name = "custom_source_to_sink",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 2: No source match → no taint
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 2: No source match ──\n");
    {
        const request_source = taint.parseSourcePattern("request.get(...)");
        const sinks = [_]taint.SinkSpec{.{
            .rule_id = "sql-injection",
            .message = "SQL injection",
            .severity = .ERROR,
            .callee = null,
            .object = "cursor",
            .method = "execute",
            .sources = &[_]taint.SourceSpec{request_source},
        }};
        const src =
            \\def handle():
            \\    user_id = get_safe_value()
            \\    cursor.execute(user_id)
        ;
        const findings = try runTaintWithSinks(&parser, src, &sinks, alloc);
        defer alloc.free(findings);

        try results.append(.{
            .name = "no_source_match",
            .passed = findings.len == 0,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 0)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 3: Source + assignment chain
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 3: Source + assignment chain ──\n");
    {
        const input_source = taint.parseSourcePattern("input(...)");
        const sinks = [_]taint.SinkSpec{.{
            .rule_id = "tainted-exec",
            .message = "tainted data to exec",
            .severity = .ERROR,
            .callee = "exec",
            .object = null,
            .method = null,
            .sources = &[_]taint.SourceSpec{input_source},
        }};
        const src =
            \\def handle():
            \\    raw = input("Enter: ")
            \\    cmd = raw
            \\    exec(cmd)
        ;
        const findings = try runTaintWithSinks(&parser, src, &sinks, alloc);
        defer alloc.free(findings);
        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });

        try results.append(.{
            .name = "source_assignment_chain",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 4: Backward compat — no sources = use params
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 4: Backward compat (params) ──\n");
    {
        const sinks = [_]taint.SinkSpec{.{
            .rule_id = "tainted-exec",
            .message = "tainted exec",
            .severity = .ERROR,
            .callee = "exec",
            .object = null,
            .method = null,
            .sources = &.{}, // empty = use params
        }};
        const src =
            \\def process(user_input):
            \\    exec(user_input)
        ;
        const findings = try runTaintWithSinks(&parser, src, &sinks, alloc);
        defer alloc.free(findings);

        try results.append(.{
            .name = "backward_compat_params",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 5: Multiple sources — any match taints
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 5: Multiple sources ──\n");
    {
        const sources = [_]taint.SourceSpec{
            taint.parseSourcePattern("request.get(...)"),
            taint.parseSourcePattern("input(...)"),
            taint.parseSourcePattern("os.environ.get(...)"),
        };
        const sinks = [_]taint.SinkSpec{.{
            .rule_id = "tainted-exec",
            .message = "tainted exec",
            .severity = .ERROR,
            .callee = "exec",
            .object = null,
            .method = null,
            .sources = &sources,
        }};
        const src =
            \\def handle():
            \\    data = input("Enter: ")
            \\    exec(data)
        ;
        const findings = try runTaintWithSinks(&parser, src, &sinks, alloc);
        defer alloc.free(findings);

        try results.append(.{
            .name = "multiple_sources",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 6: YAML parsing end-to-end
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 6: YAML parsing ──\n");
    {
        const yaml =
            \\rules:
            \\  - id: python.security.sql-injection-custom
            \\    pattern: cursor.execute(...)
            \\    sources: [request.get(...), input(...)]
            \\    message: SQL injection from user input
            \\    languages: [python]
            \\    severity: ERROR
            \\    tier: 2
        ;
        const rules = try rule.parseRules(yaml, alloc);
        defer alloc.free(rules);
        const compiled = try rule.compileRules(rules, alloc);
        defer alloc.free(compiled);

        // Verify sources were parsed
        const has_sources = rules.len > 0 and rules[0].sources.len == 2;
        try stdout.print("  Parsed {d} rules, sources: {d}\n", .{
            rules.len,
            if (rules.len > 0) rules[0].sources.len else 0,
        });

        // Extract sinks and verify sources are attached
        const sinks = try taint.extractSinks(compiled, "python", alloc);
        defer alloc.free(sinks);

        const sinks_have_sources = sinks.len > 0 and sinks[0].sources.len == 2;

        // Run against test code
        const src =
            \\def handle():
            \\    user_id = request.get("id")
            \\    cursor.execute(user_id)
        ;
        const findings = try runTaintWithSinks(&parser, src, sinks, alloc);
        defer alloc.free(findings);

        try results.append(.{
            .name = "yaml_parsing_e2e",
            .passed = has_sources and sinks_have_sources and findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "sources_parsed={}, sinks_have_sources={}, findings={d}", .{ has_sources, sinks_have_sources, findings.len }),
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
    const verdict: []const u8 = if (fail_count == 0) "H17 CONFIRMED" else "H17 NEEDS WORK";
    writer.print("  Verdict: {s}\n\n", .{verdict}) catch return;
}
