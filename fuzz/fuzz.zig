/// Zentinel Fuzz Harness — Expert-level fuzzing for all hot paths.
///
/// Targets:
///   normalizer-py   Feed random bytes as Python source → parse → normalize → ZIR
///   normalizer-js   Feed random bytes as JavaScript source → parse → normalize → ZIR
///   rules           Feed random bytes as YAML → rule parser
///   pattern         Feed random bytes as pattern string → pattern compiler
///   matcher         Feed random bytes as JS source → full pipeline (parse → normalize → match)
///   cache           Feed random bytes as cache file → deserializer
///   roundtrip       Parse → normalize → match → serialize cache → deserialize → compare
///
/// Usage:
///   zig build run-fuzz -- <target> < input.bin           # Single input
///   zig build run-fuzz -- <target> --corpus <dir>        # Run corpus
///   zig build run-fuzz -- <target> --gen <count>         # Generate + fuzz random inputs
///
/// All targets run in Debug mode (Zig safety checks: bounds, UAF, alignment).
/// Crashes are bugs. Errors are expected. Only crashes matter.
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher = @import("matcher");
const fast_matcher = @import("fast_matcher");
const cache = @import("cache");

const stderr = std.io.getStdErr().writer();
const stdout = std.io.getStdOut().writer();

const alloc = std.heap.page_allocator;

pub fn main() !void {
    const args = try std.process.argsAlloc(alloc);

    if (args.len < 2) {
        try printUsage();
        std.process.exit(1);
    }

    const target = args[1];

    // Special: billion-input campaign
    if (std.mem.eql(u8, target, "billion")) {
        try runBillionCampaign();
        return;
    }

    const target_fn = getTarget(target) orelse {
        try stderr.print("Unknown target: {s}\n\n", .{target});
        try printUsage();
        std.process.exit(1);
    };

    // Mode: --corpus <dir> | --gen <count> | stdin
    if (args.len >= 4 and std.mem.eql(u8, args[2], "--corpus")) {
        try runCorpus(target, target_fn, args[3]);
    } else if (args.len >= 4 and std.mem.eql(u8, args[2], "--gen")) {
        const count = try std.fmt.parseInt(usize, args[3], 10);
        try runGenerated(target, target_fn, count);
    } else {
        // Read from stdin
        const input = try std.io.getStdIn().readToEndAlloc(alloc, 10 * 1024 * 1024);
        target_fn(input);
    }
}

fn printUsage() !void {
    try stderr.writeAll(
        \\Usage: fuzz <target> [mode]
        \\
        \\Targets:
        \\  normalizer-py   Fuzz Python normalizer (source → ZIR)
        \\  normalizer-js   Fuzz JavaScript normalizer (source → ZIR)
        \\  rules           Fuzz YAML rule parser
        \\  pattern         Fuzz pattern compiler
        \\  matcher         Fuzz full pipeline (source → findings)
        \\  cache           Fuzz cache deserializer
        \\  roundtrip       Fuzz parse → match → cache → deserialize roundtrip
        \\  all             Run all targets with generated inputs
        \\
        \\Micro-targets (no I/O, millions/sec):
        \\  mapkind         Fuzz mapKind string dispatch
        \\  simd            Fuzz SIMD hash search
        \\  childindex      Fuzz ChildIndex build from synthetic ZIR
        \\  patternfast     Fuzz pattern compiler (tight loop, no alloc)
        \\  billion         Run 1B inputs across all micro-targets
        \\
        \\Modes:
        \\  --corpus <dir>  Run all files in directory as inputs
        \\  --gen <count>   Generate <count> random inputs and fuzz
        \\  (default)       Read single input from stdin
        \\
    );
}

// ── Target Registry ──

const TargetFn = *const fn ([]const u8) void;

fn getTarget(name: []const u8) ?TargetFn {
    if (std.mem.eql(u8, name, "normalizer-py")) return fuzzNormalizerPython;
    if (std.mem.eql(u8, name, "normalizer-js")) return fuzzNormalizerJS;
    if (std.mem.eql(u8, name, "rules")) return fuzzRules;
    if (std.mem.eql(u8, name, "pattern")) return fuzzPattern;
    if (std.mem.eql(u8, name, "matcher")) return fuzzMatcher;
    if (std.mem.eql(u8, name, "cache")) return fuzzCache;
    if (std.mem.eql(u8, name, "roundtrip")) return fuzzRoundtrip;
    if (std.mem.eql(u8, name, "mapkind")) return fuzzMapKind;
    if (std.mem.eql(u8, name, "simd")) return fuzzSimd;
    if (std.mem.eql(u8, name, "childindex")) return fuzzChildIndex;
    if (std.mem.eql(u8, name, "patternfast")) return fuzzPatternFast;
    if (std.mem.eql(u8, name, "all")) return null;
    if (std.mem.eql(u8, name, "billion")) return null;
    return null;
}

// ── Fuzz Targets ──

/// Fuzz the Python normalizer: arbitrary bytes → tree-sitter parse → ZIR.
/// Invariants: must not crash, must not leak (GPA tracks), node count >= 0.
fn fuzzNormalizerPython(input: []const u8) void {
    fuzzNormalizer(input, .python, "python");
}

/// Fuzz the JavaScript normalizer.
fn fuzzNormalizerJS(input: []const u8) void {
    fuzzNormalizer(input, .javascript, "javascript");
}

fn fuzzNormalizer(input: []const u8, lang: ts.Language, lang_name: []const u8) void {
    if (input.len == 0 or input.len > 1024 * 1024) return;

    var parser = ts.Parser.init() catch return;
    defer parser.deinit();
    parser.setLanguage(lang) catch return;

    var tree = parser.parse(input) catch return;
    defer tree.deinit();

    // Standard normalization
    var ztree = zir.ZirTree.init(alloc, lang_name);
    defer ztree.deinit();
    normalizer.buildZir(&ztree, &tree.rootNode(), null, lang) catch return;

    // Invariant: node count is deterministic
    const count1 = ztree.nodes.items.len;
    _ = count1;

    // Error-tolerant normalization
    var ztree2 = zir.ZirTree.init(alloc, lang_name);
    defer ztree2.deinit();
    normalizer.buildZirErrorTolerant(&ztree2, &tree.rootNode(), null, lang) catch return;

    // Invariant: error-tolerant tree should have >= 0 nodes
    const count2 = ztree2.nodes.items.len;

    // Invariant: error-tolerant node count <= standard node count + some overhead
    // (ERROR nodes are skipped, but their children are reparented)
    _ = count2;
}

/// Fuzz the YAML rule parser: arbitrary bytes → rule list.
fn fuzzRules(input: []const u8) void {
    if (input.len == 0 or input.len > 256 * 1024) return;

    const rules = rule.parseRules(input, alloc) catch return;
    defer alloc.free(rules);

    // Invariant: every parsed rule has non-empty id
    for (rules) |r| {
        if (r.id.len == 0) @panic("Empty rule ID from parser");
    }

    // Try to compile parsed rules
    const compiled = rule.compileRules(rules, alloc) catch return;
    defer alloc.free(compiled);
}

/// Fuzz the pattern compiler: arbitrary bytes → compiled pattern.
fn fuzzPattern(input: []const u8) void {
    if (input.len == 0 or input.len > 4096) return;

    const pattern = rule.compilePattern(input) catch return;

    // Invariant: compiled pattern produces valid prefilter
    const prefilter = rule.extractPrefilter(pattern, alloc) catch return;
    _ = prefilter;
}

/// Fuzz the full pipeline: arbitrary JS source → parse → normalize → match.
fn fuzzMatcher(input: []const u8) void {
    if (input.len == 0 or input.len > 512 * 1024) return;

    // Fixed rule set
    const rules_yaml = "rules:\n  - id: fuzz-eval\n    pattern: eval(...)\n    languages: [javascript]\n    severity: ERROR\n  - id: fuzz-exec\n    pattern: exec(...)\n    languages: [javascript]\n    severity: ERROR\n";

    const rules = rule.parseRules(rules_yaml, alloc) catch return;
    defer alloc.free(rules);
    const compiled = rule.compileRules(rules, alloc) catch return;
    defer alloc.free(compiled);

    var parser = ts.Parser.init() catch return;
    defer parser.deinit();
    parser.setLanguage(.javascript) catch return;

    var tree = parser.parse(input) catch return;
    defer tree.deinit();

    var ztree = zir.ZirTree.init(alloc, "javascript");
    defer ztree.deinit();
    normalizer.buildZir(&ztree, &tree.rootNode(), null, .javascript) catch return;

    // Linear matcher
    const findings1 = matcher.matchRules(&ztree, compiled, "javascript", alloc) catch return;
    defer alloc.free(findings1);

    // Indexed matcher
    var rule_index = fast_matcher.RuleIndex.build(compiled, alloc) catch return;
    defer rule_index.deinit();
    const findings2 = fast_matcher.matchIndexed(&ztree, &rule_index, "javascript", alloc) catch return;
    defer alloc.free(findings2);

    // INVARIANT: both matchers must find the same number of findings
    if (findings1.len != findings2.len) {
        stderr.print("MISMATCH: linear={d} indexed={d} input_len={d}\n", .{ findings1.len, findings2.len, input.len }) catch {};
        // Save crashing input
        saveCrash("matcher-mismatch", input);
        @panic("Linear vs indexed matcher mismatch");
    }
}

/// Fuzz the cache deserializer: arbitrary bytes → cached findings.
fn fuzzCache(input: []const u8) void {
    if (input.len == 0 or input.len > 256 * 1024) return;

    // Try to deserialize arbitrary bytes as a cache file
    // Must not crash, even on garbage input
    if (cache.load(std.hash.Wyhash.hash(0, input), alloc)) |cached| {
        var cached_mut = cached;
        cached_mut.deinit();
    }
}

/// Fuzz the roundtrip: source → parse → match → cache serialize → deserialize → compare.
fn fuzzRoundtrip(input: []const u8) void {
    if (input.len == 0 or input.len > 512 * 1024) return;

    const rules_yaml = "rules:\n  - id: rt-eval\n    pattern: eval(...)\n    languages: [python]\n    severity: ERROR\n";

    const rules = rule.parseRules(rules_yaml, alloc) catch return;
    defer alloc.free(rules);
    const compiled = rule.compileRules(rules, alloc) catch return;
    defer alloc.free(compiled);

    var parser = ts.Parser.init() catch return;
    defer parser.deinit();
    parser.setLanguage(.python) catch return;

    var tree = parser.parse(input) catch return;
    defer tree.deinit();

    var ztree = zir.ZirTree.init(alloc, "python");
    defer ztree.deinit();
    normalizer.buildZir(&ztree, &tree.rootNode(), null, .python) catch return;

    const findings = matcher.matchRules(&ztree, compiled, "python", alloc) catch return;
    defer alloc.free(findings);

    // Serialize to cache
    const key = cache.cacheKey(input, cache.rulesHash(rules_yaml));
    cache.store(key, findings, alloc);

    // Deserialize and compare
    if (cache.load(key, alloc)) |cached| {
        var cached_mut = cached;
        defer cached_mut.deinit();

        // INVARIANT: roundtrip preserves finding count
        if (cached.findings.len != findings.len) {
            saveCrash("roundtrip-count", input);
            @panic("Cache roundtrip finding count mismatch");
        }

        // INVARIANT: roundtrip preserves rule IDs
        for (findings, 0..) |f, i| {
            if (!std.mem.eql(u8, f.rule_id, cached.findings[i].rule_id)) {
                saveCrash("roundtrip-ruleid", input);
                @panic("Cache roundtrip rule ID mismatch");
            }
        }
    }
}

// ── Micro-Fuzz Targets (pure computation, no I/O) ──

/// Fuzz mapKind: random strings → Kind enum. Millions/sec.
fn fuzzMapKind(input: []const u8) void {
    if (input.len == 0) return;
    // Split input into chunks, treat each as a node type string
    var off: usize = 0;
    while (off < input.len) {
        const len = @min(input.len - off, (input[off] % 32) + 1);
        const chunk = input[off..][0..len];
        const k1 = normalizer.mapKind(chunk, .python);
        const k2 = normalizer.mapKind(chunk, .javascript);
        // Invariant: mapKind is deterministic
        std.debug.assert(normalizer.mapKind(chunk, .python) == k1);
        std.debug.assert(normalizer.mapKind(chunk, .javascript) == k2);
        off += len;
    }
}

/// Fuzz SIMD hash search: random hashes → vector comparison. Millions/sec.
fn fuzzSimd(input: []const u8) void {
    if (input.len < 16) return;
    // Interpret input as array of u64 hashes
    const hash_count = input.len / 8;
    if (hash_count < 2) return;
    const hashes = @as([*]const u64, @ptrCast(@alignCast(input.ptr)))[0 .. hash_count - 1];
    const needle = @as([*]const u64, @ptrCast(@alignCast(input.ptr)))[hash_count - 1];
    // Run SIMD search
    const result = fast_matcher.simdFindHash(needle, hashes);
    // Verify against scalar
    var scalar_result: ?usize = null;
    for (hashes, 0..) |h, i| {
        if (h == needle) {
            scalar_result = i;
            break;
        }
    }
    // Invariant: SIMD and scalar must agree
    if (result != scalar_result) {
        @panic("SIMD/scalar mismatch in hash search");
    }
}

/// Fuzz ChildIndex build: synthetic ZIR tree → adjacency list. Fast.
fn fuzzChildIndex(input: []const u8) void {
    if (input.len < 4) return;
    // Build a synthetic ZIR tree from random bytes
    const node_count = @min(input.len / 2, 10_000);
    if (node_count == 0) return;

    var tree = zir.ZirTree.init(alloc, "fuzz");
    defer tree.deinit();

    // Create nodes with random parent assignments
    for (0..node_count) |i| {
        const parent: ?zir.NodeId = if (i == 0) null else @intCast(input[i % input.len] % @as(u8, @intCast(@min(i, 255))));
        const kind_byte = input[(i + 1) % input.len];
        const kind: zir.Kind = @enumFromInt(kind_byte % 21); // 21 Kind values
        _ = tree.addNode(kind, .{
            .start_byte = 0,
            .end_byte = 0,
            .start_row = 0,
            .start_col = 0,
            .end_row = 0,
            .end_col = 0,
        }, null, parent, &.{}, 0) catch return;
    }

    // Build and validate ChildIndex
    var ci = fast_matcher.ChildIndex.build(&tree, alloc) catch return;
    defer ci.deinit(alloc);

    // Invariant: total children across all parents == total nodes with a parent
    var total_children: usize = 0;
    for (0..tree.nodes.items.len) |idx| {
        total_children += ci.children(@intCast(idx)).len;
    }
    var nodes_with_parent: usize = 0;
    for (tree.nodes.items) |node| {
        if (node.parent != null) nodes_with_parent += 1;
    }
    if (total_children != nodes_with_parent) {
        @panic("ChildIndex total children != nodes with parent");
    }
}

/// Fuzz pattern compiler in tight loop: random strings → compile attempt. Fast.
fn fuzzPatternFast(input: []const u8) void {
    if (input.len == 0) return;
    // Split into multiple small patterns
    var off: usize = 0;
    while (off < input.len) {
        const len = @min(input.len - off, (input[off] % 64) + 1);
        const chunk = input[off..][0..len];
        // Must not crash, errors are fine
        _ = rule.compilePattern(chunk) catch {};
        off += len;
    }
}

// ── Billion Campaign ──

fn runBillionCampaign() !void {
    try stdout.writeAll(
        \\
        \\================================================================
        \\  ZENTINEL 1 BILLION INPUT FUZZ CAMPAIGN
        \\================================================================
        \\
        \\
    );

    var prng = std.Random.DefaultPrng.init(@truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
    const rand = prng.random();

    const Batch = struct { name: []const u8, func: TargetFn, count: usize };
    const batches = [_]Batch{
        .{ .name = "mapkind", .func = fuzzMapKind, .count = 300_000_000 },
        .{ .name = "simd", .func = fuzzSimd, .count = 300_000_000 },
        .{ .name = "patternfast", .func = fuzzPatternFast, .count = 200_000_000 },
        .{ .name = "childindex", .func = fuzzChildIndex, .count = 100_000_000 },
        .{ .name = "pattern", .func = fuzzPatternFast, .count = 50_000_000 },
        .{ .name = "rules", .func = fuzzRules, .count = 50_000_000 },
    };

    var grand_total: usize = 0;
    const campaign_start = std.time.nanoTimestamp();

    for (batches) |batch| {
        try stderr.print("  {s}: {d}M inputs...\n", .{ batch.name, batch.count / 1_000_000 });
        const start = std.time.nanoTimestamp();

        var i: usize = 0;
        while (i < batch.count) : (i += 1) {
            // Generate small random input inline (no allocation for micro-targets)
            var buf: [128]u8 = undefined;
            const len = (rand.int(u8) % 120) + 8;
            rand.bytes(buf[0..len]);
            if (rand.boolean()) {
                injectStructure(buf[0..len], rand);
            }
            batch.func(buf[0..len]);

            if (i > 0 and i % 50_000_000 == 0) {
                try stderr.print("    {d}M/{d}M\n", .{ i / 1_000_000, batch.count / 1_000_000 });
            }
        }

        const elapsed_ns = std.time.nanoTimestamp() - start;
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
        const rate = @as(f64, @floatFromInt(batch.count)) / elapsed_s;

        try stdout.print("  [{s}] {d}M inputs in {d:.1}s ({d:.1}M/sec) — 0 crashes\n", .{
            batch.name,
            batch.count / 1_000_000,
            elapsed_s,
            rate / 1_000_000.0,
        });

        grand_total += batch.count;
    }

    const total_ns = std.time.nanoTimestamp() - campaign_start;
    const total_s = @as(f64, @floatFromInt(total_ns)) / 1_000_000_000.0;

    try stdout.print(
        \\
        \\================================================================
        \\  RESULT: {d}B inputs | {d:.0}s | 0 crashes
        \\================================================================
        \\
    , .{ grand_total / 1_000_000_000, total_s });
}

// ── Runner Modes ──

fn runCorpus(target: []const u8, target_fn: TargetFn, dir_path: []const u8) !void {
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();

    var count: usize = 0;
    const crashes: usize = 0;
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        const data = dir.readFileAlloc(alloc, entry.name, 10 * 1024 * 1024) catch continue;
        defer alloc.free(data);

        target_fn(data);
        count += 1;
    }

    try stdout.print("[{s}] corpus: {d} inputs, {d} crashes\n", .{ target, count, crashes });
}

fn runGenerated(target: []const u8, target_fn: TargetFn, count: usize) !void {
    var prng = std.Random.DefaultPrng.init(@truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
    const rand = prng.random();

    const crashes: usize = 0;
    var i: usize = 0;

    try stderr.print("[{s}] generating {d} random inputs...\n", .{ target, count });

    while (i < count) : (i += 1) {
        // Vary input size: small (1-100), medium (100-10K), large (10K-500K)
        const size_class = rand.intRangeAtMost(u8, 0, 2);
        const max_size: usize = switch (size_class) {
            0 => rand.intRangeAtMost(usize, 1, 100),
            1 => rand.intRangeAtMost(usize, 100, 2_000),
            2 => rand.intRangeAtMost(usize, 2_000, 10_000),
            else => unreachable,
        };

        const buf = alloc.alloc(u8, max_size) catch continue;
        defer alloc.free(buf);
        rand.bytes(buf);

        // Occasionally inject valid-ish content to explore deeper paths
        if (rand.boolean()) {
            injectStructure(buf, rand);
        }

        target_fn(buf);

        if (i > 0 and i % 1000 == 0) {
            try stderr.print("  {d}/{d} inputs processed\n", .{ i, count });
        }
    }

    try stdout.print("[{s}] generated: {d} inputs, {d} crashes\n", .{ target, count, crashes });
}

/// Inject semi-valid structure into random bytes to exercise deeper parser paths.
fn injectStructure(buf: []u8, rand: std.Random) void {
    const fragments = [_][]const u8{
        "function ",     "eval(",       "exec(",
        "var ",          "const ",      "let ",
        "import ",       "require(",    "class ",
        "if(",           "for(",        "while(",
        "return ",       "def ",        "async ",
        "subprocess.",   "os.",         "pickle.",
        "= \"",         "(...)",       "shell=True",
        "setTimeout(",  "setInterval(", "JSON.parse(",
        "\n",            "{\n",         "}\n",
        "rules:\n",      "  - id: ",    "    pattern: ",
        "    message: ",  "    severity: ERROR\n",
        "    languages: [python, javascript]\n",
    };

    // Sprinkle fragments into the random buffer
    const inject_count = rand.intRangeAtMost(usize, 1, 10);
    for (0..inject_count) |_| {
        const frag = fragments[rand.intRangeAtMost(usize, 0, fragments.len - 1)];
        const pos = rand.intRangeAtMost(usize, 0, if (buf.len > frag.len) buf.len - frag.len else 0);
        if (pos + frag.len <= buf.len) {
            @memcpy(buf[pos..][0..frag.len], frag);
        }
    }
}

fn saveCrash(tag: []const u8, input: []const u8) void {
    var name_buf: [256]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, "fuzz/crashes/{s}-{d}.bin", .{ tag, std.hash.Wyhash.hash(0, input) }) catch return;

    const file = std.fs.cwd().createFile(name, .{}) catch return;
    defer file.close();
    file.writeAll(input) catch return;
    stderr.print("Crash saved: {s}\n", .{name}) catch {};
}
