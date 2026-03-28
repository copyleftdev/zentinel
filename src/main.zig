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
const agent_output = @import("agent_output");
const taint = @import("taint");
const crossfile = @import("crossfile");
const web = @import("web");
const columnar = @import("columnar");
const cache = @import("cache");

const stderr = std.io.getStdErr().writer();
const stdout = std.io.getStdOut().writer();

const Format = enum { text, json_sarif, agent };

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
    } else if (std.mem.eql(u8, command, "serve")) {
        try web.runServe(args[2..], allocator);
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
        \\  serve [options]              Start web scanner dashboard
        \\  help                         Show this help
        \\
        \\Scan Options:
        \\  --config, -c <path>          Rules file or directory (repeatable)
        \\  --format, -f <format>        Output format: text, sarif, agent (default: text)
        \\  --max-tier <0-3>             Maximum rule tier to run (default: all)
        \\
        \\Serve Options:
        \\  --port, -p <port>            HTTP port (default: 8000)
        \\  --rules, -r <path>           Rules directory (default: rules)
        \\
        \\Examples:
        \\  zent scan src/*.py --config rules/python-security.yaml
        \\  zent scan src/*.go -c rules/go-security.yaml -c rules/community/go-community.yaml
        \\  zent scan src/ --config rules/              # loads all .yaml in directory
        \\  zent scan app.js --config rules.yaml --format agent
        \\  zent serve --port 8080
        \\
    );
}

fn runScan(args: []const []const u8, allocator: std.mem.Allocator) !void {
    var files = std.ArrayList([]const u8).init(allocator);
    defer files.deinit();
    var config_paths = std.ArrayList([]const u8).init(allocator);
    defer config_paths.deinit();
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
            try config_paths.append(args[i]);
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
            } else if (std.mem.eql(u8, args[i], "agent") or std.mem.eql(u8, args[i], "json")) {
                format = .agent;
            } else {
                try stderr.print("Unknown format: {s} (use 'text', 'sarif', or 'agent')\n", .{args[i]});
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

    if (config_paths.items.len == 0) {
        try stderr.writeAll("Error: --config is required\n");
        std.process.exit(1);
    }

    // Expand directory configs: if a config path is a directory, load all .yaml files in it
    var expanded_configs = std.ArrayList([]const u8).init(allocator);
    defer expanded_configs.deinit();

    for (config_paths.items) |cp| {
        // Check if it's a directory
        if (std.fs.cwd().openDir(cp, .{ .iterate = true })) |dir_val| {
            var dir = dir_val;
            defer dir.close();
            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                if (entry.kind == .file and (std.mem.endsWith(u8, entry.name, ".yaml") or std.mem.endsWith(u8, entry.name, ".yml"))) {
                    const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cp, entry.name });
                    try expanded_configs.append(full);
                }
            }
            // Also check subdirectories (e.g., community/)
            var iter2 = dir.iterate();
            while (try iter2.next()) |entry| {
                if (entry.kind == .directory) {
                    var subdir = dir.openDir(entry.name, .{ .iterate = true }) catch continue;
                    defer subdir.close();
                    var sub_iter = subdir.iterate();
                    while (sub_iter.next() catch null) |sub_entry| {
                        if (sub_entry.kind == .file and (std.mem.endsWith(u8, sub_entry.name, ".yaml") or std.mem.endsWith(u8, sub_entry.name, ".yml"))) {
                            const full = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ cp, entry.name, sub_entry.name });
                            try expanded_configs.append(full);
                        }
                    }
                }
            }
        } else |_| {
            // Not a directory — treat as a file
            try expanded_configs.append(cp);
        }
    }

    // Load and compile rules from all config files
    // IMPORTANT: YAML sources must stay alive — rules hold slices into them
    var all_rules = std.ArrayList(rule.Rule).init(allocator);
    defer all_rules.deinit();
    var yaml_sources = std.ArrayList([]const u8).init(allocator);
    defer {
        for (yaml_sources.items) |ys| allocator.free(ys);
        yaml_sources.deinit();
    }
    var all_yaml_hash = std.ArrayList(u8).init(allocator);
    defer all_yaml_hash.deinit();

    for (expanded_configs.items) |config_file| {
        const yaml_source = std.fs.cwd().readFileAlloc(allocator, config_file, 2 * 1024 * 1024) catch |err| {
            try stderr.print("Warning: could not read {s}: {s}\n", .{ config_file, @errorName(err) });
            continue;
        };

        try all_yaml_hash.appendSlice(yaml_source);

        const rules = rule.parseRules(yaml_source, allocator) catch |err| {
            try stderr.print("Warning: could not parse {s}: {s}\n", .{ config_file, @errorName(err) });
            allocator.free(yaml_source);
            continue;
        };
        try yaml_sources.append(yaml_source); // Keep alive
        for (rules) |r| try all_rules.append(r);
    }

    if (all_rules.items.len == 0) {
        try stderr.writeAll("Error: no rules loaded from config files\n");
        std.process.exit(1);
    }

    const all_compiled = try rule.compileRules(all_rules.items, allocator);
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

    const rules_h = cache.rulesHash(all_yaml_hash.items);

    // Build rule dispatch index (once for entire scan)
    var rule_index = try fast_matcher.RuleIndex.build(compiled, allocator);
    defer rule_index.deinit();

    if (max_tier) |mt| {
        try stderr.print("Loaded {d} rules ({d} compiled, tier <= {d}) from {d} config(s)\n", .{ all_rules.items.len, compiled.len, mt, expanded_configs.items.len });
    } else {
        try stderr.print("Loaded {d} rules ({d} compiled) from {d} config(s)\n", .{ all_rules.items.len, compiled.len, expanded_configs.items.len });
    }

    // Initialize parser
    var parser = try ts.Parser.init();
    defer parser.deinit();

    // Source content map for agent output (file path → source text)
    var source_map = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = source_map.iterator();
        while (it.next()) |entry| allocator.free(entry.value_ptr.*);
        source_map.deinit();
    }

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

        // Store source for agent output context
        if (format == .agent) {
            try source_map.put(file_path, try allocator.dupe(u8, source));
        }

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

        // Cache miss — check ZIR cache first
        const zir_key = columnar.zirCacheKey(source);
        var zir_path_buf: [256]u8 = undefined;
        const zir_path = columnar.zirCachePath(zir_key, &zir_path_buf);

        var ztree: zir.ZirTree = undefined;
        var ztree_from_columnar = false;

        if (std.fs.cwd().readFileAlloc(allocator, zir_path, 10 * 1024 * 1024)) |zir_data| {
            // ZIR cache hit — deserialize columnar
            if (columnar.deserialize(zir_data, allocator)) |ct| {
                var ct_mut = ct;
                ztree = ct_mut.toZirTree(allocator) catch blk: {
                    ct_mut.deinit();
                    allocator.free(zir_data);
                    break :blk zir.ZirTree.init(allocator, lang.name);
                };
                ct_mut.deinit();
                ztree_from_columnar = true;
            } else |_| {
                ztree = zir.ZirTree.init(allocator, lang.name);
            }
            allocator.free(zir_data);

            if (!ztree_from_columnar) {
                // Deserialization failed — parse normally
                try parser.setLanguage(lang.ts_lang);
                var tree2 = try parser.parse(source);
                defer tree2.deinit();
                try normalizer.buildZir(&ztree, &tree2.rootNode(), null, lang.ts_lang);
            }
        } else |_| {
            // ZIR cache miss — parse and normalize
            try parser.setLanguage(lang.ts_lang);
            var tree2 = try parser.parse(source);
            defer tree2.deinit();
            ztree = zir.ZirTree.init(allocator, lang.name);
            try normalizer.buildZir(&ztree, &tree2.rootNode(), null, lang.ts_lang);
        }
        defer ztree.deinit();

        // Build ChildIndex + write ZIR cache if this was a fresh parse
        var ci = try fast_matcher.ChildIndex.build(&ztree, allocator);
        defer ci.deinit(allocator);

        if (!ztree_from_columnar) {
            // Write ZIR cache for next time
            if (columnar.serialize(&ztree, &ci, allocator)) |serialized| {
                defer allocator.free(serialized);
                std.fs.cwd().makePath(".zentinel-cache") catch {};
                if (std.fs.cwd().createFile(zir_path, .{})) |f| {
                    defer f.close();
                    f.writeAll(serialized) catch {};
                } else |_| {}
            } else |_| {}
        }

        var findings_list = std.ArrayList(matcher.Finding).init(allocator);

        // Tier 0/1: structural + argument matching
        const structural_findings = try fast_matcher.matchWithIndex(&ztree, &rule_index, &ci, lang.name, allocator);
        try findings_list.appendSlice(structural_findings);
        allocator.free(structural_findings);

        // Tier 2: taint analysis (only if Tier 2 rules exist)
        const tier2_sinks = try taint.extractSinks(compiled, lang.name, allocator);
        defer allocator.free(tier2_sinks);
        if (tier2_sinks.len > 0) {
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

    // Tier 3: Cross-file analysis (if any tier>=3 rules exist)
    const tier3_sinks = try taint.extractSinksAtTier(compiled, 3, allocator);
    defer allocator.free(tier3_sinks);

    if (tier3_sinks.len > 0 and files.items.len > 1) {
        // Build cross-file index: re-parse all files, extract exports/imports
        var cross_index = crossfile.CrossFileIndex.init(allocator);
        defer cross_index.deinit();

        for (files.items) |file_path| {
            const lang2 = detectLanguage(file_path) orelse continue;
            const source2 = std.fs.cwd().readFileAlloc(allocator, file_path, 10 * 1024 * 1024) catch continue;
            defer allocator.free(source2);

            try parser.setLanguage(lang2.ts_lang);
            var tree2 = try parser.parse(source2);
            defer tree2.deinit();

            var ztree2 = zir.ZirTree.init(allocator, lang2.name);
            // Don't defer deinit — ownership transfers to cross_index
            try normalizer.buildZir(&ztree2, &tree2.rootNode(), null, lang2.ts_lang);

            var ci2 = try fast_matcher.ChildIndex.build(&ztree2, allocator);
            const exports = try crossfile.extractExports(&ztree2, &ci2, allocator);
            const imports = try crossfile.extractImports(&ztree2, &ci2, allocator);

            try cross_index.files.put(file_path, .{
                .tree = ztree2,
                .ci = ci2,
                .lang = lang2.name,
                .exports = exports,
                .imports = imports,
            });
        }

        // Run cross-file analysis for each file
        for (files.items) |file_path| {
            const cf_findings = try crossfile.analyzeCrossFile(
                &cross_index,
                file_path,
                tier3_sinks,
                files.items,
                allocator,
            );

            if (cf_findings.len > 0) {
                if (format == .text) {
                    for (cf_findings) |f| {
                        try stdout.print("{s}:{d}:{d}: {s} [{s}] ({s}) [cross-file]\n", .{
                            file_path,
                            f.span.start_row + 1,
                            f.span.start_col + 1,
                            f.message,
                            @tagName(f.severity),
                            f.rule_id,
                        });
                    }
                }
                total_findings += cf_findings.len;
            }
            allocator.free(cf_findings);
        }
    }

    // Structured output (written after all files are scanned)
    if (format == .json_sarif) {
        try sarif.writeSarif(stdout, all_file_results.items, compiled);
    }

    const elapsed = timer.read();
    const elapsed_us = @as(f64, @floatFromInt(elapsed)) / 1000.0;
    const elapsed_ms = elapsed_us / 1000.0;

    if (format == .agent) {
        // Agent JSON: structured output with context, categories, confidence, fixes
        const AgentFileResult = struct { path: []const u8, findings: []const matcher.Finding };
        var agent_results = std.ArrayList(AgentFileResult).init(allocator);
        defer agent_results.deinit();
        for (all_file_results.items) |fr| {
            try agent_results.append(.{ .path = fr.path, .findings = fr.findings });
        }
        try agent_output.writeAgentJson(stdout, agent_results.items, files_scanned, elapsed_ms, &source_map);
        try stdout.writeAll("\n");
    }

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
