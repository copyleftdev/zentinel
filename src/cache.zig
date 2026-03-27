/// Incremental scan cache.
/// Content-addressed: key = hash(file_content ++ rules_hash).
/// Stores findings per file so unchanged files skip parse/normalize/match.
const std = @import("std");
const rule = @import("rule");
const matcher = @import("matcher");
const zir = @import("zir");

const CACHE_DIR = ".zentinel-cache";

/// Compute a 64-bit hash of a byte slice.
fn hash64(data: []const u8) u64 {
    return std.hash.Wyhash.hash(0, data);
}

/// Compute the rules hash from the raw YAML source.
pub fn rulesHash(yaml_source: []const u8) u64 {
    return hash64(yaml_source);
}

/// Compute a cache key for a file given its content and rules hash.
pub fn cacheKey(file_content: []const u8, rules_h: u64) u64 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, rules_h, .little);
    const file_h = hash64(file_content);
    var combined: [16]u8 = undefined;
    std.mem.writeInt(u64, combined[0..8], file_h, .little);
    std.mem.writeInt(u64, combined[8..16], rules_h, .little);
    return hash64(&combined);
}

/// A cached set of findings for one file.
pub const CachedFindings = struct {
    findings: []matcher.Finding,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *CachedFindings) void {
        for (self.findings) |f| {
            self.allocator.free(f.rule_id);
            self.allocator.free(f.message);
        }
        self.allocator.free(self.findings);
    }
};

/// Try to load cached findings for a given cache key.
/// Returns null on miss.
pub fn load(key: u64, allocator: std.mem.Allocator) ?CachedFindings {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, CACHE_DIR ++ "/{x}.cache", .{key}) catch return null;

    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    const data = file.readToEndAlloc(allocator, 1024 * 1024) catch return null;
    defer allocator.free(data);

    return deserialize(data, allocator);
}

/// Store findings for a given cache key.
pub fn store(key: u64, findings: []const matcher.Finding, allocator: std.mem.Allocator) void {
    // Ensure cache dir exists
    std.fs.cwd().makePath(CACHE_DIR) catch return;

    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, CACHE_DIR ++ "/{x}.cache", .{key}) catch return;

    const file = std.fs.cwd().createFile(path, .{}) catch return;
    defer file.close();

    serialize(file.writer(), findings, allocator) catch return;
}

/// Serialize findings as a simple line-based format.
/// Each line: rule_id\tstart_row\tstart_col\tend_row\tend_col\tseverity_int\tmessage
fn serialize(writer: anytype, findings: []const matcher.Finding, allocator: std.mem.Allocator) !void {
    _ = allocator;
    for (findings) |f| {
        try writer.print("{s}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{s}\n", .{
            f.rule_id,
            f.span.start_byte,
            f.span.end_byte,
            f.span.start_row,
            f.span.start_col,
            f.span.end_row,
            f.span.end_col,
            @intFromEnum(f.severity),
            f.message,
        });
    }
}

/// Deserialize findings from line-based format.
fn deserialize(data: []const u8, allocator: std.mem.Allocator) ?CachedFindings {
    var findings_list = std.ArrayList(matcher.Finding).init(allocator);

    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const f = parseLine(line, allocator) orelse continue;
        findings_list.append(f) catch {
            // Cleanup on failure
            for (findings_list.items) |item| {
                allocator.free(item.rule_id);
                allocator.free(item.message);
            }
            findings_list.deinit();
            return null;
        };
    }

    return .{
        .findings = findings_list.toOwnedSlice() catch {
            for (findings_list.items) |item| {
                allocator.free(item.rule_id);
                allocator.free(item.message);
            }
            findings_list.deinit();
            return null;
        },
        .allocator = allocator,
    };
}

fn parseLine(line: []const u8, allocator: std.mem.Allocator) ?matcher.Finding {
    var fields = std.mem.splitScalar(u8, line, '\t');

    const rule_id_raw = fields.next() orelse return null;
    const start_byte_s = fields.next() orelse return null;
    const end_byte_s = fields.next() orelse return null;
    const start_row_s = fields.next() orelse return null;
    const start_col_s = fields.next() orelse return null;
    const end_row_s = fields.next() orelse return null;
    const end_col_s = fields.next() orelse return null;
    const severity_s = fields.next() orelse return null;
    const message_raw = fields.rest();

    const rule_id = allocator.dupe(u8, rule_id_raw) catch return null;
    const message = allocator.dupe(u8, message_raw) catch {
        allocator.free(rule_id);
        return null;
    };

    return .{
        .rule_id = rule_id,
        .span = .{
            .start_byte = std.fmt.parseInt(u32, start_byte_s, 10) catch return null,
            .end_byte = std.fmt.parseInt(u32, end_byte_s, 10) catch return null,
            .start_row = std.fmt.parseInt(u32, start_row_s, 10) catch return null,
            .start_col = std.fmt.parseInt(u32, start_col_s, 10) catch return null,
            .end_row = std.fmt.parseInt(u32, end_row_s, 10) catch return null,
            .end_col = std.fmt.parseInt(u32, end_col_s, 10) catch return null,
        },
        .severity = @enumFromInt(std.fmt.parseInt(u8, severity_s, 10) catch return null),
        .message = message,
        .node_id = 0,
    };
}
