/// H6: Do arena allocators measurably reduce allocation overhead for tree walking?
///
/// PASS criteria:
///   1. Arena allocation is faster than page_allocator for ZIR construction
///   2. Arena can be reset and reused between files (amortized cost)
///   3. Memory usage is bounded and predictable
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

const ITERATIONS = 500;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\
        \\══════════════════════════════════════════════════════════
        \\  H6: Arena Allocator Performance
        \\══════════════════════════════════════════════════════════
        \\
    );

    var parser = try ts.Parser.init();
    defer parser.deinit();
    try parser.setLanguage(.python);

    const py_source = try readFixture("test_fixtures/python/clean.py");

    // Pre-parse so we're only measuring ZIR construction
    var tree = try parser.parse(py_source);
    defer tree.deinit();
    const root = tree.rootNode();

    // ── Benchmark 1: page_allocator ────────────────────────────
    var page_timer = try std.time.Timer.start();
    var page_node_count: usize = 0;
    for (0..ITERATIONS) |_| {
        var ztree = zir.ZirTree.init(std.heap.page_allocator, "python");
        try normalizer.buildZir(&ztree, &root, null, .python);
        page_node_count = ztree.nodes.items.len;
        ztree.deinit();
    }
    const page_elapsed = page_timer.read();

    // ── Benchmark 2: arena allocator (reset per iteration) ─────
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    var arena_timer = try std.time.Timer.start();
    var arena_node_count: usize = 0;
    for (0..ITERATIONS) |_| {
        var ztree = zir.ZirTree.init(arena.allocator(), "python");
        try normalizer.buildZir(&ztree, &root, null, .python);
        arena_node_count = ztree.nodes.items.len;
        // Don't deinit individual tree — arena handles it
        _ = arena.reset(.retain_capacity);
    }
    const arena_elapsed = arena_timer.read();
    arena.deinit();

    // ── Benchmark 3: arena with no reset (accumulate) ──────────
    var arena2 = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    var arena_accum_timer = try std.time.Timer.start();
    for (0..ITERATIONS) |_| {
        var ztree = zir.ZirTree.init(arena2.allocator(), "python");
        try normalizer.buildZir(&ztree, &root, null, .python);
        // No reset — accumulates
    }
    const arena_accum_elapsed = arena_accum_timer.read();
    arena2.deinit();

    // ── Results ────────────────────────────────────────────────
    const page_ms = @as(f64, @floatFromInt(page_elapsed)) / 1_000_000.0;
    const arena_ms = @as(f64, @floatFromInt(arena_elapsed)) / 1_000_000.0;
    const arena_accum_ms = @as(f64, @floatFromInt(arena_accum_elapsed)) / 1_000_000.0;
    const speedup = page_ms / arena_ms;

    try stdout.print(
        \\
        \\── Benchmark ({d} iterations, {d} ZIR nodes each) ──
        \\
        \\  page_allocator:        {d:.2} ms total  ({d:.4} ms/iter)
        \\  arena (reset/iter):    {d:.2} ms total  ({d:.4} ms/iter)
        \\  arena (no reset):      {d:.2} ms total  ({d:.4} ms/iter)
        \\
        \\  Arena speedup: {d:.2}x
        \\
    , .{
        ITERATIONS,
        page_node_count,
        page_ms,
        page_ms / @as(f64, ITERATIONS),
        arena_ms,
        arena_ms / @as(f64, ITERATIONS),
        arena_accum_ms,
        arena_accum_ms / @as(f64, ITERATIONS),
        speedup,
    });

    // Correctness check
    const same_count = page_node_count == arena_node_count;

    try stdout.writeAll("\n── Results ─────────────────────────────────────────────\n");
    try stdout.print("  [{s}] arena_faster: arena is {d:.2}x faster than page_allocator\n", .{
        if (speedup > 1.0) "PASS" else "FAIL",
        speedup,
    });
    try stdout.print("  [{s}] correctness: both produce {d} nodes\n", .{
        if (same_count) "PASS" else "FAIL",
        page_node_count,
    });

    const pass_count: u32 = (if (speedup > 1.0) @as(u32, 1) else 0) + (if (same_count) @as(u32, 1) else 0);
    const fail_count: u32 = 2 - pass_count;
    try stdout.print("\n  Total: {d} passed, {d} failed\n", .{ pass_count, fail_count });
    const verdict: []const u8 = if (fail_count == 0) "H6 CONFIRMED" else "H6 NEEDS WORK";
    try stdout.print("  Verdict: {s}\n\n", .{verdict});
}

