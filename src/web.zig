/// Zentinel Web Server — high-performance Zig HTTP server for the scanner dashboard.
///
/// Serves the frontend and handles /api/scan requests by cloning repos
/// and running the scanning pipeline directly in-process.
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");
const rule = @import("rule");
const matcher = @import("matcher");
const fast_matcher = @import("fast_matcher");
const taint = @import("taint");

const stderr_writer = std.io.getStdErr().writer();

// ── Embedded Frontend ──
const INDEX_HTML = @embedFile("web_assets/index.html");
const LOGO_PNG = @embedFile("web_assets/logo.png");

// ── Types ──

const Finding = struct {
    file: []const u8,
    line: u32,
    col: u32,
    message: []const u8,
    severity: []const u8,
    rule_id: []const u8,
};

// ── Public API ──

pub fn runServe(args: []const []const u8, allocator: std.mem.Allocator) !void {
    var port: u16 = 8000;
    var rules_dir: []const u8 = "rules";

    // Parse args
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") or std.mem.eql(u8, args[i], "-p")) {
            i += 1;
            if (i < args.len) port = std.fmt.parseInt(u16, args[i], 10) catch 8000;
        } else if (std.mem.eql(u8, args[i], "--rules") or std.mem.eql(u8, args[i], "-r")) {
            i += 1;
            if (i < args.len) rules_dir = args[i];
        }
    }

    try stderr_writer.print(
        \\
        \\  Zentinel Web Scanner
        \\  Listening on http://localhost:{d}
        \\  Rules: {s}/
        \\
        \\
    , .{ port, rules_dir });

    const address = std.net.Address.parseIp("0.0.0.0", port) catch unreachable;
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    while (true) {
        const conn = server.accept() catch continue;
        handleConnection(conn, rules_dir, allocator) catch |err| {
            stderr_writer.print("Connection error: {s}\n", .{@errorName(err)}) catch {};
        };
    }
}

fn handleConnection(conn: std.net.Server.Connection, rules_dir: []const u8, allocator: std.mem.Allocator) !void {
    defer conn.stream.close();

    var buf: [8192]u8 = undefined;
    var http = std.http.Server.init(conn, &buf);

    var req = http.receiveHead() catch return;

    const path = req.head.target;

    if (std.mem.eql(u8, path, "/")) {
        try serveBytes(&req, INDEX_HTML, "text/html");
    } else if (std.mem.eql(u8, path, "/static/logo.png")) {
        try serveBytes(&req, LOGO_PNG, "image/png");
    } else if (std.mem.eql(u8, path, "/api/scan") and req.head.method == .POST) {
        try handleScan(&req, rules_dir, allocator);
    } else {
        try serve404(&req);
    }
}

fn serveBytes(req: *std.http.Server.Request, body: []const u8, content_type: []const u8) !void {
    try req.respond(body, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = content_type },
        },
    });
}

fn serve404(req: *std.http.Server.Request) !void {
    try req.respond("Not Found", .{
        .status = .not_found,
        .extra_headers = &.{
            .{ .name = "content-type", .value = "text/plain" },
        },
    });
}

fn serveJson(req: *std.http.Server.Request, json_body: []const u8) !void {
    try req.respond(json_body, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "access-control-allow-origin", .value = "*" },
        },
    });
}

fn serveError(req: *std.http.Server.Request, status: std.http.Status, message: []const u8, allocator: std.mem.Allocator) !void {
    const body = try std.fmt.allocPrint(allocator, "{{\"detail\":\"{s}\"}}", .{message});
    defer allocator.free(body);
    try req.respond(body, .{
        .status = status,
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
        },
    });
}

// ── Scan Handler ──

fn handleScan(req: *std.http.Server.Request, rules_dir: []const u8, allocator: std.mem.Allocator) !void {
    // Read request body
    var reader = try req.reader();
    const body = try reader.readAllAlloc(allocator, 4096);
    defer allocator.free(body);

    // Extract repo_url from JSON (simple extraction)
    const repo_url = extractJsonString(body, "repo_url") orelse {
        try serveError(req, .bad_request, "Missing repo_url", allocator);
        return;
    };

    // Validate URL
    if (!std.mem.startsWith(u8, repo_url, "https://github.com/")) {
        try serveError(req, .bad_request, "Only GitHub HTTPS URLs supported", allocator);
        return;
    }

    // Extract repo name
    const repo_name = extractRepoName(repo_url);

    var timer = try std.time.Timer.start();

    // Clone repo to temp dir
    const tmp_dir = cloneRepo(repo_url, allocator) catch {
        try serveError(req, .bad_request, "Failed to clone repository", allocator);
        return;
    };
    defer {
        // Clean up temp dir
        std.fs.deleteTreeAbsolute(tmp_dir) catch {};
        allocator.free(tmp_dir);
    }

    // Find scannable files
    var files_by_lang = findFiles(tmp_dir, allocator) catch {
        try serveError(req, .bad_request, "No scannable files found", allocator);
        return;
    };
    defer {
        var it = files_by_lang.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |f| allocator.free(f);
            entry.value_ptr.deinit();
        }
        files_by_lang.deinit();
    }

    // Run scans
    var all_findings = std.ArrayList(Finding).init(allocator);
    defer {
        for (all_findings.items) |f| {
            allocator.free(f.file);
        }
        all_findings.deinit();
    }

    var total_files: usize = 0;
    var lang_counts = std.StringHashMap(usize).init(allocator);
    defer lang_counts.deinit();

    const lang_rule_pairs = [_]struct { lang: []const u8, ts_lang: ts.Language, rule_files: []const []const u8 }{
        .{ .lang = "python", .ts_lang = .python, .rule_files = &.{ "python-security.yaml", "community/python-community.yaml" } },
        .{ .lang = "javascript", .ts_lang = .javascript, .rule_files = &.{ "javascript-security.yaml", "community/javascript-community.yaml" } },
        .{ .lang = "typescript", .ts_lang = .typescript, .rule_files = &.{ "typescript-security.yaml", "community/typescript-community.yaml" } },
        .{ .lang = "go", .ts_lang = .go, .rule_files = &.{ "go-security.yaml", "community/go-community.yaml" } },
    };

    var parser = try ts.Parser.init();
    defer parser.deinit();

    for (lang_rule_pairs) |lrp| {
        if (files_by_lang.get(lrp.lang)) |file_list| {
            const file_count = file_list.items.len;
            try lang_counts.put(lrp.lang, file_count);
            total_files += file_count;

            for (lrp.rule_files) |rule_filename| {
                const rule_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ rules_dir, rule_filename }) catch continue;
                defer allocator.free(rule_path);

                const yaml_source = std.fs.cwd().readFileAlloc(allocator, rule_path, 2 * 1024 * 1024) catch continue;
                defer allocator.free(yaml_source);

                const rules = rule.parseRules(yaml_source, allocator) catch continue;
                defer allocator.free(rules);
                const compiled = rule.compileRules(rules, allocator) catch continue;
                defer allocator.free(compiled);

                var rule_index = fast_matcher.RuleIndex.build(compiled, allocator) catch continue;
                defer rule_index.deinit();

                for (file_list.items) |file_path| {
                    const source = std.fs.cwd().readFileAlloc(allocator, file_path, 10 * 1024 * 1024) catch continue;
                    defer allocator.free(source);

                    parser.setLanguage(lrp.ts_lang) catch continue;
                    var tree = parser.parse(source) catch continue;
                    defer tree.deinit();

                    var ztree = zir.ZirTree.init(allocator, lrp.lang);
                    defer ztree.deinit();
                    normalizer.buildZir(&ztree, &tree.rootNode(), null, lrp.ts_lang) catch continue;

                    const findings = fast_matcher.matchIndexed(&ztree, &rule_index, lrp.lang, allocator) catch continue;
                    defer allocator.free(findings);

                    // Strip tmp_dir prefix from file path
                    const rel_path = if (std.mem.indexOf(u8, file_path, "repo/")) |idx|
                        file_path[idx + 5 ..]
                    else
                        file_path;

                    for (findings) |f| {
                        try all_findings.append(.{
                            .file = try allocator.dupe(u8, rel_path),
                            .line = f.span.start_row + 1,
                            .col = f.span.start_col + 1,
                            .message = f.message,
                            .severity = @tagName(f.severity),
                            .rule_id = f.rule_id,
                        });
                    }
                }
            }
        }
    }

    const elapsed_ns = timer.read();
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;

    // Build JSON response
    const json_resp = try buildJsonResponse(
        repo_name,
        total_files,
        all_findings.items,
        elapsed_ms,
        &lang_counts,
        allocator,
    );
    defer allocator.free(json_resp);

    try serveJson(req, json_resp);
}

// ── Helpers ──

fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    // Simple JSON string extraction: find "key":"value"
    const search = std.fmt.allocPrint(std.heap.page_allocator, "\"{s}\"", .{key}) catch return null;
    defer std.heap.page_allocator.free(search);

    const key_pos = std.mem.indexOf(u8, json, search) orelse return null;
    const after_key = json[key_pos + search.len ..];

    // Skip : and whitespace
    var i: usize = 0;
    while (i < after_key.len and (after_key[i] == ':' or after_key[i] == ' ' or after_key[i] == '"')) : (i += 1) {}
    if (i == 0) return null;

    // Find closing quote
    const start = i;
    while (i < after_key.len and after_key[i] != '"') : (i += 1) {}
    if (i >= after_key.len) return null;

    return after_key[start..i];
}

fn extractRepoName(url: []const u8) []const u8 {
    // "https://github.com/owner/repo" → "owner/repo"
    const prefix = "https://github.com/";
    if (std.mem.startsWith(u8, url, prefix)) {
        return url[prefix.len..];
    }
    return url;
}

fn cloneRepo(url: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    // Create temp directory path
    var tmp_buf: [256]u8 = undefined;
    const timestamp = @as(u64, @intCast(std.time.timestamp()));
    const tmp_path = try std.fmt.bufPrint(&tmp_buf, "/tmp/zentinel-{d}", .{timestamp});
    const owned_path = try allocator.dupe(u8, tmp_path);

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "git", "clone", "--depth", "1", "--single-branch", url, try std.fmt.allocPrint(allocator, "{s}/repo", .{owned_path}) },
    });
    allocator.free(result.stdout);
    allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        allocator.free(owned_path);
        return error.CloneFailed;
    }

    return owned_path;
}

const LangExtMap = struct { ext: []const u8, lang: []const u8 };
const EXTENSIONS = [_]LangExtMap{
    .{ .ext = ".py", .lang = "python" },
    .{ .ext = ".js", .lang = "javascript" },
    .{ .ext = ".jsx", .lang = "javascript" },
    .{ .ext = ".ts", .lang = "typescript" },
    .{ .ext = ".tsx", .lang = "typescript" },
    .{ .ext = ".go", .lang = "go" },
};

fn findFiles(tmp_dir: []const u8, allocator: std.mem.Allocator) !std.StringHashMap(std.ArrayList([]const u8)) {
    var result = std.StringHashMap(std.ArrayList([]const u8)).init(allocator);

    const repo_path = try std.fmt.allocPrint(allocator, "{s}/repo", .{tmp_dir});
    defer allocator.free(repo_path);

    // Walk the directory tree
    var walker = try std.fs.openDirAbsolute(repo_path, .{ .iterate = true });
    defer walker.close();

    var iter = walker.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;

        // Skip hidden files
        if (name[0] == '.') continue;

        for (EXTENSIONS) |ext_map| {
            if (std.mem.endsWith(u8, name, ext_map.ext)) {
                const full_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ repo_path, name });
                const gop = try result.getOrPut(ext_map.lang);
                if (!gop.found_existing) gop.value_ptr.* = std.ArrayList([]const u8).init(allocator);
                try gop.value_ptr.append(full_path);
                break;
            }
        }
    }

    // Also scan subdirectories (one level deep for simplicity)
    var dir_iter = walker.iterate();
    while (try dir_iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (entry.name[0] == '.' or
            std.mem.eql(u8, entry.name, "node_modules") or
            std.mem.eql(u8, entry.name, "vendor") or
            std.mem.eql(u8, entry.name, "venv") or
            std.mem.eql(u8, entry.name, "__pycache__") or
            std.mem.eql(u8, entry.name, "dist") or
            std.mem.eql(u8, entry.name, "build")) continue;

        var subdir = walker.openDir(entry.name, .{ .iterate = true }) catch continue;
        defer subdir.close();

        var sub_iter = subdir.iterate();
        while (sub_iter.next() catch null) |sub_entry| {
            if (sub_entry.kind != .file) continue;
            if (sub_entry.name[0] == '.') continue;

            for (EXTENSIONS) |ext_map| {
                if (std.mem.endsWith(u8, sub_entry.name, ext_map.ext)) {
                    const full_path = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ repo_path, entry.name, sub_entry.name });
                    const gop = try result.getOrPut(ext_map.lang);
                    if (!gop.found_existing) gop.value_ptr.* = std.ArrayList([]const u8).init(allocator);
                    try gop.value_ptr.append(full_path);
                    break;
                }
            }
        }
    }

    return result;
}

fn buildJsonResponse(
    repo_name: []const u8,
    total_files: usize,
    findings: []const Finding,
    duration_ms: f64,
    lang_counts: *const std.StringHashMap(usize),
    allocator: std.mem.Allocator,
) ![]const u8 {
    var json = std.ArrayList(u8).init(allocator);
    const w = json.writer();

    try w.print("{{\"repo\":\"{s}\",\"files_scanned\":{d},\"duration_ms\":{d:.1},", .{ repo_name, total_files, duration_ms });

    // Languages
    try w.writeAll("\"languages\":{");
    var first = true;
    var lang_iter = lang_counts.iterator();
    while (lang_iter.next()) |entry| {
        if (!first) try w.writeAll(",");
        try w.print("\"{s}\":{d}", .{ entry.key_ptr.*, entry.value_ptr.* });
        first = false;
    }
    try w.writeAll("},");

    // Severity counts
    var err_count: usize = 0;
    var warn_count: usize = 0;
    var info_count: usize = 0;
    for (findings) |f| {
        if (std.mem.eql(u8, f.severity, "ERROR")) err_count += 1
        else if (std.mem.eql(u8, f.severity, "WARNING")) warn_count += 1
        else info_count += 1;
    }
    try w.print("\"severity_counts\":{{\"ERROR\":{d},\"WARNING\":{d},\"INFO\":{d}}},", .{ err_count, warn_count, info_count });

    // Tier counts
    var t0: usize = 0;
    var t1: usize = 0;
    var t23: usize = 0;
    for (findings) |f| {
        if (std.mem.indexOf(u8, f.rule_id, "taint") != null or std.mem.indexOf(u8, f.rule_id, "crossfile") != null) {
            t23 += 1;
        } else if (std.mem.indexOf(u8, f.rule_id, "shell-true") != null or
            std.mem.indexOf(u8, f.rule_id, "fstring") != null or
            std.mem.indexOf(u8, f.rule_id, "precise") != null or
            std.mem.indexOf(u8, f.rule_id, "template") != null or
            std.mem.indexOf(u8, f.rule_id, "new-md5") != null or
            std.mem.indexOf(u8, f.rule_id, "new-sha1") != null)
        {
            t1 += 1;
        } else {
            t0 += 1;
        }
    }
    try w.print("\"tier_counts\":{{\"Tier 0\":{d},\"Tier 1\":{d},\"Tier 2/3\":{d}}},", .{ t0, t1, t23 });

    // Top rules
    var rule_map = std.StringHashMap(usize).init(allocator);
    defer rule_map.deinit();
    for (findings) |f| {
        const gop = try rule_map.getOrPut(f.rule_id);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }

    // Sort top rules (simple: collect all, sort by count)
    const RuleCount = struct { rule: []const u8, count: usize };
    var top_rules = std.ArrayList(RuleCount).init(allocator);
    defer top_rules.deinit();

    var rule_iter = rule_map.iterator();
    while (rule_iter.next()) |entry| {
        try top_rules.append(.{ .rule = entry.key_ptr.*, .count = entry.value_ptr.* });
    }

    // Simple insertion sort for top 15
    for (top_rules.items, 0..) |_, ii| {
        var max_idx = ii;
        for (ii + 1..top_rules.items.len) |jj| {
            if (top_rules.items[jj].count > top_rules.items[max_idx].count) max_idx = jj;
        }
        if (max_idx != ii) {
            const tmp = top_rules.items[ii];
            top_rules.items[ii] = top_rules.items[max_idx];
            top_rules.items[max_idx] = tmp;
        }
    }

    try w.writeAll("\"top_rules\":[");
    const top_n = @min(top_rules.items.len, 15);
    for (top_rules.items[0..top_n], 0..) |rc, idx| {
        if (idx > 0) try w.writeAll(",");
        try w.print("{{\"rule\":\"{s}\",\"count\":{d}}}", .{ rc.rule, rc.count });
    }
    try w.writeAll("],");

    // Findings array
    try w.writeAll("\"findings\":[");
    for (findings, 0..) |f, idx| {
        if (idx > 0) try w.writeAll(",");
        // Escape message for JSON
        try w.print("{{\"file\":\"{s}\",\"line\":{d},\"col\":{d},\"severity\":\"{s}\",\"rule_id\":\"{s}\",\"message\":\"", .{
            f.file, f.line, f.col, f.severity, f.rule_id,
        });
        // Escape message characters
        for (f.message) |c| {
            switch (c) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                '\n' => try w.writeAll("\\n"),
                '\r' => {},
                else => try w.writeByte(c),
            }
        }
        try w.writeAll("\"}");
    }
    try w.writeAll("]}");

    return json.toOwnedSlice();
}
