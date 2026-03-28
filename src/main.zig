/// zent — Zentinel CLI
///
/// Usage:
///   zent scan <files...> --config <rules.yaml> [--format text|sarif]
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher = @import("matcher");
const fast_matcher = @import("fast_matcher");
const sarif = @import("sarif");
const taint = @import("taint");
const cache = @import("cache");

const stderr = std.io.getStdErr().writer();
const stdout = std.io.getStdOut().writer();

const Format = enum { text, json_sarif };

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage();
        std.process.exit(1);
    }

    const command = args[1];
    if (std.mem.eql(u8, command, "scan")) {
        try runScan(args[2..], allocator);
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        try printUsage();
    } else {
        try stderr.print("Unknown command: {s}\n\n", .{command});
        try printUsage();
        std.process.exit(1);
    }
}

fn printUsage() !void {
    try stderr.writeAll(
        \\Usage: zent <command> [options]
        \\
        \\Commands:
        \\  scan <files...> [options]    Scan files for issues
        \\  help                         Show this help
        \\
        \\Scan Options:
        \\  --config, -c <path>          Rules file (required)
        \\  --format, -f <text|sarif>    Output format (default: text)
        \\  --max-tier <0-3>             Maximum rule tier to run (default: all)
        \\
        \\Examples:
        \\  zent scan src/*.py --config rules.yaml
        \\  zent scan app.js --config rules.yaml --format sarif
        \\
    );
}

fn runScan(args: []const []const u8, allocator: std.mem.Allocator) !void {
    var files = std.ArrayList([]const u8).init(allocator);
    defer files.deinit();
    var config_path: ?[]const u8 = null;
    var format: Format = .text;
    var max_tier: ?u8 = null;

    // Parse scan args
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--config") or std.mem.eql(u8, args[i], "-c")) {
            i += 1;
            if (i >= args.len) {
                try stderr.writeAll("Error: --config requires a path argument\n");
                std.process.exit(1);
            }
            config_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--format") or std.mem.eql(u8, args[i], "-f")) {
            i += 1;
            if (i >= args.len) {
                try stderr.writeAll("Error: --format requires an argument (text or sarif)\n");
                std.process.exit(1);
            }
            if (std.mem.eql(u8, args[i], "sarif")) {
                format = .json_sarif;
            } else if (std.mem.eql(u8, args[i], "text")) {
                format = .text;
            } else {
                try stderr.print("Unknown format: {s} (use 'text' or 'sarif')\n", .{args[i]});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, args[i], "--max-tier")) {
            i += 1;
            if (i >= args.len) {
                try stderr.writeAll("Error: --max-tier requires a value (0-3)\n");
                std.process.exit(1);
            }
            max_tier = std.fmt.parseInt(u8, args[i], 10) catch {
                try stderr.print("Invalid tier value: {s} (use 0-3)\n", .{args[i]});
                std.process.exit(1);
            };
        } else if (args[i].len > 0 and args[i][0] == '-') {
            try stderr.print("Unknown option: {s}\n", .{args[i]});
            std.process.exit(1);
        } else {
            try files.append(args[i]);
        }
    }

    if (files.items.len == 0) {
        try stderr.writeAll("Error: no files specified\n");
        std.process.exit(1);
    }

    if (config_path == null) {
        try stderr.writeAll("Error: --config is required\n");
        std.process.exit(1);
    }

    // Load and compile rules
    const yaml_source = std.fs.cwd().readFileAlloc(allocator, config_path.?, 1024 * 1024) catch |err| {
        try stderr.print("Error reading {s}: {s}\n", .{ config_path.?, @errorName(err) });
        std.process.exit(1);
    };
    defer allocator.free(yaml_source);

    const rules = try rule.parseRules(yaml_source, allocator);
    defer allocator.free(rules);

    const all_compiled = try rule.compileRules(rules, allocator);
    defer allocator.free(all_compiled);

    // Filter by max tier if specified
    const compiled = if (max_tier) |mt| blk: {
        var filtered = std.ArrayList(rule.CompiledRule).init(allocator);
        for (all_compiled) |cr| {
            if (cr.rule.tier <= mt) try filtered.append(cr);
        }
        break :blk try filtered.toOwnedSlice();
    } else all_compiled;
    defer if (max_tier != null) allocator.free(compiled);

    const rules_h = cache.rulesHash(yaml_source);

    // Build rule dispatch index (once for entire scan)
    var rule_index = try fast_matcher.RuleIndex.build(compiled, allocator);
    defer rule_index.deinit();

    if (max_tier) |mt| {
        try stderr.print("Loaded {d} rules ({d} compiled, tier <= {d})\n", .{ rules.len, compiled.len, mt });
    } else {
        try stderr.print("Loaded {d} rules ({d} compiled)\n", .{ rules.len, compiled.len });
    }

    // Initialize parser
    var parser = try ts.Parser.init();
    defer parser.deinit();

    // Scan each file, collect results
    var all_file_results = std.ArrayList(sarif.FileFindings).init(allocator);
    defer {
        for (all_file_results.items) |fr| allocator.free(fr.findings);
        all_file_results.deinit();
    }

    var total_findings: usize = 0;
    var files_scanned: usize = 0;
    var cache_hits: usize = 0;
    var timer = try std.time.Timer.start();

    for (files.items) |file_path| {
        const lang = detectLanguage(file_path) orelse {
            try stderr.print("Skipping {s}: unsupported language\n", .{file_path});
            continue;
        };

        const source = std.fs.cwd().readFileAlloc(allocator, file_path, 10 * 1024 * 1024) catch |err| {
            try stderr.print("Error reading {s}: {s}\n", .{ file_path, @errorName(err) });
            continue;
        };
        defer allocator.free(source);

        const key = cache.cacheKey(source, rules_h);

        // Try cache first
        if (cache.load(key, allocator)) |cached| {
            if (format == .text) {
                for (cached.findings) |f| {
                    try stdout.print("{s}:{d}:{d}: {s} [{s}] ({s})\n", .{
                        file_path,
                        f.span.start_row + 1,
                        f.span.start_col + 1,
                        f.message,
                        @tagName(f.severity),
                        f.rule_id,
                    });
                }
            }

            // Transfer ownership — findings (with owned strings) go to all_file_results
            try all_file_results.append(.{ .path = file_path, .findings = cached.findings });
            total_findings += cached.findings.len;
            files_scanned += 1;
            cache_hits += 1;
            continue;
        }

        // Cache miss — full scan
        try parser.setLanguage(lang.ts_lang);
        var tree = try parser.parse(source);
        defer tree.deinit();

        var ztree = zir.ZirTree.init(allocator, lang.name);
        defer ztree.deinit();
        try normalizer.buildZir(&ztree, &tree.rootNode(), null, lang.ts_lang);

        var findings_list = std.ArrayList(matcher.Finding).init(allocator);

        // Tier 0/1: structural + argument matching
        const structural_findings = try fast_matcher.matchIndexed(&ztree, &rule_index, lang.name, allocator);
        try findings_list.appendSlice(structural_findings);
        allocator.free(structural_findings);

        // Tier 2: taint analysis (only if Tier 2 rules exist)
        const tier2_sinks = try taint.extractSinks(compiled, lang.name, allocator);
        defer allocator.free(tier2_sinks);
        if (tier2_sinks.len > 0) {
            var ci = try fast_matcher.ChildIndex.build(&ztree, allocator);
            defer ci.deinit(allocator);
            const taint_findings = try taint.analyzeTaint(&ztree, &ci, tier2_sinks, lang.name, allocator);
            try findings_list.appendSlice(taint_findings);
            allocator.free(taint_findings);
        }

        const findings = try findings_list.toOwnedSlice();

        // Store to cache
        cache.store(key, findings, allocator);

        if (format == .text) {
            for (findings) |f| {
                try stdout.print("{s}:{d}:{d}: {s} [{s}] ({s})\n", .{
                    file_path,
                    f.span.start_row + 1,
                    f.span.start_col + 1,
                    f.message,
                    @tagName(f.severity),
                    f.rule_id,
                });
            }
        }

        try all_file_results.append(.{ .path = file_path, .findings = findings });
        total_findings += findings.len;
        files_scanned += 1;
    }

    // SARIF output (written after all files are scanned)
    if (format == .json_sarif) {
        try sarif.writeSarif(stdout, all_file_results.items, compiled);
    }

    const elapsed = timer.read();
    const elapsed_us = @as(f64, @floatFromInt(elapsed)) / 1000.0;

    if (cache_hits > 0) {
        try stderr.print("\nScanned {d} file(s) in {d:.1}μs — {d} finding(s) ({d} cached)\n", .{
            files_scanned,
            elapsed_us,
            total_findings,
            cache_hits,
        });
    } else {
        try stderr.print("\nScanned {d} file(s) in {d:.1}μs — {d} finding(s)\n", .{
            files_scanned,
            elapsed_us,
            total_findings,
        });
    }

    if (total_findings > 0) {
        std.process.exit(1);
    }
}

const LangInfo = struct {
    name: []const u8,
    ts_lang: ts.Language,
};

fn detectLanguage(path: []const u8) ?LangInfo {
    const ext = std.fs.path.extension(path);
    if (std.mem.eql(u8, ext, ".py")) return .{ .name = "python", .ts_lang = .python };
    if (std.mem.eql(u8, ext, ".js")) return .{ .name = "javascript", .ts_lang = .javascript };
    if (std.mem.eql(u8, ext, ".jsx")) return .{ .name = "javascript", .ts_lang = .javascript };
    if (std.mem.eql(u8, ext, ".go")) return .{ .name = "go", .ts_lang = .go };
    if (std.mem.eql(u8, ext, ".ts")) return .{ .name = "typescript", .ts_lang = .typescript };
    if (std.mem.eql(u8, ext, ".tsx")) return .{ .name = "typescript", .ts_lang = .typescript };
    return null;
}
