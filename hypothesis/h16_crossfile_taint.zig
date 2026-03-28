/// H16: Cross-file taint tracking (Tier 3)
///
/// PASS criteria:
///   1. Import + tainted call → 1 finding across file boundary
///   2. Safe argument → 0 findings
///   3. Multi-hop in callee → 1 finding
///   4. Module-level (no function param) → 0 findings
///   5. Performance within bounds
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher_mod = @import("matcher");
const fast_matcher = @import("fast_matcher");
const taint = @import("taint");
const crossfile = @import("crossfile");

const Result = struct {
    name: []const u8,
    passed: bool,
    detail: []const u8,
};

/// Build a StoredFile from source code.
fn buildStoredFile(
    parser: *ts.Parser,
    source: []const u8,
    lang: ts.Language,
    lang_name: []const u8,
    alloc: std.mem.Allocator,
) !crossfile.StoredFile {
    try parser.setLanguage(lang);
    var tree = try parser.parse(source);
    defer tree.deinit();

    var ztree = zir.ZirTree.init(alloc, lang_name);
    try normalizer.buildZir(&ztree, &tree.rootNode(), null, lang);

    var ci = try fast_matcher.ChildIndex.build(&ztree, alloc);
    const exports = try crossfile.extractExports(&ztree, &ci, alloc);
    const imports = try crossfile.extractImports(&ztree, &ci, alloc);

    return .{
        .tree = ztree,
        .ci = ci,
        .lang = lang_name,
        .exports = exports,
        .imports = imports,
    };
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\
        \\══════════════════════════════════════════════════════════
        \\  H16: Cross-File Taint Tracking (Tier 3)
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results.deinit();
    const alloc = std.heap.page_allocator;

    var parser = try ts.Parser.init();
    defer parser.deinit();

    const exec_sink = [_]taint.SinkSpec{.{
        .rule_id = "crossfile-exec",
        .message = "tainted data flows across module boundary to exec()",
        .severity = .ERROR,
        .callee = "exec",
        .object = null,
        .method = null,
    }};

    // ═══════════════════════════════════════════════════════
    // Test 1: Import + tainted call
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 1: Import + tainted call ──\n");
    {
        const caller_src =
            \\from sink_module import process
            \\def handle(user_input):
            \\    process(user_input)
        ;
        const callee_src =
            \\def process(data):
            \\    exec(data)
        ;

        var index = crossfile.CrossFileIndex.init(alloc);
        defer index.deinit();

        var caller_file = try buildStoredFile(&parser, caller_src, .python, "python", alloc);
        var callee_file = try buildStoredFile(&parser, callee_src, .python, "python", alloc);

        try index.files.put("caller.py", caller_file);
        try index.files.put("sink_module.py", callee_file);

        const file_paths = [_][]const u8{ "caller.py", "sink_module.py" };
        const findings = try crossfile.analyzeCrossFile(&index, "caller.py", &exec_sink, &file_paths, alloc);
        defer alloc.free(findings);

        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });

        // Prevent double-free: nullify the stored files since index owns them
        _ = &caller_file;
        _ = &callee_file;

        try results.append(.{
            .name = "import_tainted_call",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 2: Safe argument
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 2: Safe argument ──\n");
    {
        const caller_src =
            \\from sink_module import process
            \\def handle(user_input):
            \\    process("safe_constant")
        ;
        const callee_src =
            \\def process(data):
            \\    exec(data)
        ;

        var index = crossfile.CrossFileIndex.init(alloc);
        defer index.deinit();

        try index.files.put("caller.py", try buildStoredFile(&parser, caller_src, .python, "python", alloc));
        try index.files.put("sink_module.py", try buildStoredFile(&parser, callee_src, .python, "python", alloc));

        const file_paths = [_][]const u8{ "caller.py", "sink_module.py" };
        const findings = try crossfile.analyzeCrossFile(&index, "caller.py", &exec_sink, &file_paths, alloc);
        defer alloc.free(findings);

        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });

        try results.append(.{
            .name = "safe_argument",
            .passed = findings.len == 0,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 0)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 3: Multi-hop in callee
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 3: Multi-hop in callee ──\n");
    {
        const caller_src =
            \\from sink_module import process
            \\def handle(user_input):
            \\    process(user_input)
        ;
        const callee_src =
            \\def process(data):
            \\    cmd = data
            \\    exec(cmd)
        ;

        var index = crossfile.CrossFileIndex.init(alloc);
        defer index.deinit();

        try index.files.put("caller.py", try buildStoredFile(&parser, caller_src, .python, "python", alloc));
        try index.files.put("sink_module.py", try buildStoredFile(&parser, callee_src, .python, "python", alloc));

        const file_paths = [_][]const u8{ "caller.py", "sink_module.py" };
        const findings = try crossfile.analyzeCrossFile(&index, "caller.py", &exec_sink, &file_paths, alloc);
        defer alloc.free(findings);

        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });

        try results.append(.{
            .name = "multi_hop_callee",
            .passed = findings.len == 1,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 1)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 4: Module-level call (no function param source)
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 4: Module-level (no param source) ──\n");
    {
        const caller_src =
            \\from sink_module import process
            \\safe = "hello"
            \\process(safe)
        ;
        const callee_src =
            \\def process(data):
            \\    exec(data)
        ;

        var index = crossfile.CrossFileIndex.init(alloc);
        defer index.deinit();

        try index.files.put("caller.py", try buildStoredFile(&parser, caller_src, .python, "python", alloc));
        try index.files.put("sink_module.py", try buildStoredFile(&parser, callee_src, .python, "python", alloc));

        const file_paths = [_][]const u8{ "caller.py", "sink_module.py" };
        const findings = try crossfile.analyzeCrossFile(&index, "caller.py", &exec_sink, &file_paths, alloc);
        defer alloc.free(findings);

        for (findings) |f| try stdout.print("  {s} at {d}:{d}\n", .{ f.rule_id, f.span.start_row + 1, f.span.start_col + 1 });

        // Module-level code has no function params as taint source, so should be 0
        try results.append(.{
            .name = "module_level_no_param",
            .passed = findings.len == 0,
            .detail = try std.fmt.allocPrint(alloc, "{d} findings (expected 0)", .{findings.len}),
        });
    }

    // ═══════════════════════════════════════════════════════
    // Test 5: Performance
    // ═══════════════════════════════════════════════════════
    try stdout.writeAll("\n── Test 5: Performance ──\n");
    {
        const caller_src = try std.fs.cwd().readFileAlloc(alloc, "test_fixtures/python/clean.py", 1024 * 1024);
        defer alloc.free(caller_src);
        const callee_src = try std.fs.cwd().readFileAlloc(alloc, "test_fixtures/python/vulnerable.py", 1024 * 1024);
        defer alloc.free(callee_src);

        var index = crossfile.CrossFileIndex.init(alloc);
        defer index.deinit();

        try index.files.put("clean.py", try buildStoredFile(&parser, caller_src, .python, "python", alloc));
        try index.files.put("vulnerable.py", try buildStoredFile(&parser, callee_src, .python, "python", alloc));

        const file_paths = [_][]const u8{ "clean.py", "vulnerable.py" };

        const ITERS = 1000;
        var timer = try std.time.Timer.start();
        for (0..ITERS) |_| {
            const f = try crossfile.analyzeCrossFile(&index, "clean.py", &exec_sink, &file_paths, alloc);
            alloc.free(f);
        }
        const ns = timer.read();
        const per_iter_us = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(ITERS)) / 1000.0;
        try stdout.print("  {d:.1}μs per cross-file analysis ({d} iters)\n", .{ per_iter_us, ITERS });

        try results.append(.{
            .name = "performance",
            .passed = per_iter_us < 10000.0, // < 10ms
            .detail = try std.fmt.allocPrint(alloc, "{d:.1}μs (target < 10000μs)", .{per_iter_us}),
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
    const verdict: []const u8 = if (fail_count == 0) "H16 CONFIRMED" else "H16 NEEDS WORK";
    writer.print("  Verdict: {s}\n\n", .{verdict}) catch return;
}
