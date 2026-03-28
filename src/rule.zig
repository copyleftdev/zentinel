/// Rule system — YAML parsing, pattern compilation, prefilter extraction.
const std = @import("std");
const zir = @import("zir");

// ── Types ──

pub const Severity = enum {
    ERROR,
    WARNING,
    INFO,

    pub fn fromString(s: []const u8) ?Severity {
        if (std.mem.eql(u8, s, "ERROR")) return .ERROR;
        if (std.mem.eql(u8, s, "WARNING")) return .WARNING;
        if (std.mem.eql(u8, s, "INFO")) return .INFO;
        return null;
    }
};

pub const Rule = struct {
    id: []const u8,
    pattern_source: []const u8,
    message: []const u8,
    languages: []const []const u8,
    severity: Severity,
    tier: u8 = 0, // 0 = structural, 1 = local reasoning, 2 = intra-procedural, 3 = cross-file
};

pub const CallPattern = struct {
    callee: []const u8, // "exec", "eval"
    has_ellipsis: bool, // ... in args
};

pub const AssignmentPattern = struct {
    lhs_is_metavar: bool, // $KEY → true
    rhs_is_string_literal: bool, // "..." → true (legacy, kept for backward compat)
    rhs_literal_kind: ?zir.LiteralKind = null, // Tier 1: require specific literal type
};

pub const MemberCallPattern = struct {
    object: []const u8, // "subprocess"
    method: []const u8, // "call"
    has_ellipsis: bool,
};

// ── Tier 1: Argument Constraints ──

pub const ArgConstraintKind = enum {
    ellipsis, // ...
    any_string, // "..."
    exact_string, // "md5"
    string_template, // f"..."
    identifier_value, // True, False, None, or any bare name
};

pub const ArgConstraint = struct {
    kind: ArgConstraintKind,
    keyword_name: ?[]const u8 = null, // non-null for keyword args (e.g., "shell" in shell=True)
    value: ?[]const u8 = null, // for exact_string ("md5") or identifier_value ("True")
};

pub const CallWithArgsPattern = struct {
    callee: []const u8,
    constraints: []const ArgConstraint,
};

pub const MemberCallWithArgsPattern = struct {
    object: []const u8,
    method: []const u8,
    constraints: []const ArgConstraint,
};

pub const CompiledPattern = union(enum) {
    call: CallPattern,
    assignment: AssignmentPattern,
    member_call: MemberCallPattern,
    call_with_args: CallWithArgsPattern,
    member_call_with_args: MemberCallWithArgsPattern,
};

pub const PrefilterReq = struct {
    required_kinds: []const zir.Kind,
    required_atoms: []const []const u8,
};

pub const CompiledRule = struct {
    rule: Rule,
    pattern: CompiledPattern,
    prefilter: PrefilterReq,
};

// ── YAML Parser (minimal subset) ──

pub fn parseRules(yaml_source: []const u8, allocator: std.mem.Allocator) ![]Rule {
    var rules = std.ArrayList(Rule).init(allocator);

    var current: ?Rule = null;
    var in_block_scalar = false;
    var block_start: usize = 0;
    var block_end: usize = 0;

    var line_iter = std.mem.splitScalar(u8, yaml_source, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, &[_]u8{ '\r', ' ' });

        // Block scalar continuation: indented lines after "pattern: |"
        if (in_block_scalar) {
            if (line.len >= 6 and line[0] == ' ' and line[1] == ' ' and line[2] == ' ' and line[3] == ' ' and line[4] == ' ' and line[5] == ' ') {
                // Still in block scalar — extend the end
                const content_start = @intFromPtr(raw_line.ptr) - @intFromPtr(yaml_source.ptr);
                block_end = @min(content_start + raw_line.len, yaml_source.len);
                continue;
            } else {
                // Block scalar ended
                if (current != null) {
                    current.?.pattern_source = std.mem.trim(u8, yaml_source[block_start..block_end], &[_]u8{ ' ', '\n', '\r' });
                }
                in_block_scalar = false;
            }
        }

        // New rule: "  - id: <value>"
        if (std.mem.indexOf(u8, line, "- id:")) |_| {
            if (current) |r| {
                if (r.id.len > 0) try rules.append(r);
            }
            const id_val = extractValue(line, "id:") orelse "";
            current = Rule{
                .id = id_val,
                .pattern_source = "",
                .message = "",
                .languages = &.{},
                .severity = .ERROR,
                .tier = 0,
            };
            continue;
        }

        if (current == null) continue;

        // pattern: value  OR  pattern: |
        if (extractValue(line, "pattern:")) |val| {
            if (std.mem.eql(u8, val, "|")) {
                in_block_scalar = true;
                const next_pos = @intFromPtr(raw_line.ptr) - @intFromPtr(yaml_source.ptr) + raw_line.len + 1;
                block_start = @min(next_pos, yaml_source.len);
                block_end = block_start;
            } else {
                current.?.pattern_source = val;
            }
            continue;
        }

        if (extractValue(line, "message:")) |val| {
            current.?.message = val;
            continue;
        }

        if (extractValue(line, "severity:")) |val| {
            current.?.severity = Severity.fromString(val) orelse .ERROR;
            continue;
        }

        if (extractValue(line, "tier:")) |val| {
            current.?.tier = std.fmt.parseInt(u8, val, 10) catch 0;
            continue;
        }

        if (extractValue(line, "languages:")) |val| {
            current.?.languages = try parseFlowList(val, allocator);
            continue;
        }
    }

    // Flush last block scalar
    if (in_block_scalar and current != null) {
        current.?.pattern_source = std.mem.trim(u8, yaml_source[block_start..block_end], &[_]u8{ ' ', '\n', '\r' });
    }

    // Flush last rule
    if (current) |r| {
        if (r.id.len > 0) try rules.append(r);
    }

    return rules.toOwnedSlice();
}

fn extractValue(line: []const u8, key: []const u8) ?[]const u8 {
    const idx = std.mem.indexOf(u8, line, key) orelse return null;
    const after = line[idx + key.len ..];
    return std.mem.trim(u8, after, &[_]u8{ ' ', '\t' });
}

fn parseFlowList(val: []const u8, allocator: std.mem.Allocator) ![]const []const u8 {
    // Parse "[python, javascript]"
    const inner = std.mem.trim(u8, val, &[_]u8{ '[', ']', ' ' });
    var items = std.ArrayList([]const u8).init(allocator);
    var iter = std.mem.splitScalar(u8, inner, ',');
    while (iter.next()) |item| {
        const trimmed = std.mem.trim(u8, item, &[_]u8{ ' ', '\t' });
        if (trimmed.len > 0) {
            try items.append(trimmed);
        }
    }
    return items.toOwnedSlice();
}

// ── Pattern Compiler ──

pub const CompileError = error{
    UnsupportedPattern,
    OutOfMemory,
};

pub fn compilePattern(pattern_source: []const u8) CompileError!CompiledPattern {
    const src = std.mem.trim(u8, pattern_source, &[_]u8{ ' ', '\n', '\r', '\t' });

    // Check for assignment pattern: contains "=" not inside parens
    if (detectAssignment(src)) {
        const has_string_rhs = std.mem.indexOf(u8, src, "\"...\"") != null;
        return .{ .assignment = .{
            .lhs_is_metavar = src.len > 0 and src[0] == '$',
            .rhs_is_string_literal = has_string_rhs,
            .rhs_literal_kind = if (has_string_rhs) .string else null,
        } };
    }

    // Extract args string for Tier 1 analysis
    const paren_idx = std.mem.indexOfScalar(u8, src, '(') orelse return CompileError.UnsupportedPattern;
    const close_idx = std.mem.lastIndexOfScalar(u8, src, ')') orelse return CompileError.UnsupportedPattern;
    if (close_idx <= paren_idx) return CompileError.UnsupportedPattern;
    const args_str = std.mem.trim(u8, src[paren_idx + 1 .. close_idx], &[_]u8{ ' ', '\t' });
    const is_simple_ellipsis = std.mem.eql(u8, args_str, "...");

    // Check for member call: "object.method(...)"
    if (detectMemberCall(src)) |mc| {
        if (is_simple_ellipsis or args_str.len == 0) {
            return .{ .member_call = .{
                .object = mc.object,
                .method = mc.method,
                .has_ellipsis = is_simple_ellipsis,
            } };
        }
        // Tier 1: parse argument constraints
        const constraints = parseArgConstraints(args_str) orelse return CompileError.UnsupportedPattern;
        return .{ .member_call_with_args = .{
            .object = mc.object,
            .method = mc.method,
            .constraints = constraints,
        } };
    }

    // Check for simple call: "func(...)"
    if (detectCall(src)) |callee| {
        if (is_simple_ellipsis or args_str.len == 0) {
            return .{ .call = .{
                .callee = callee,
                .has_ellipsis = is_simple_ellipsis,
            } };
        }
        // Tier 1: parse argument constraints
        const constraints = parseArgConstraints(args_str) orelse return CompileError.UnsupportedPattern;
        return .{ .call_with_args = .{
            .callee = callee,
            .constraints = constraints,
        } };
    }

    return CompileError.UnsupportedPattern;
}

/// Parse a comma-separated argument list into ArgConstraints.
/// Returns null if parsing fails.
fn parseArgConstraints(args_str: []const u8) ?[]const ArgConstraint {
    // Use a static buffer — patterns have bounded arg count
    const MAX_ARGS = 8;
    var buf: [MAX_ARGS]ArgConstraint = undefined;
    var count: usize = 0;

    var start: usize = 0;
    var depth: u32 = 0;
    var i: usize = 0;

    while (i <= args_str.len) : (i += 1) {
        const at_end = i == args_str.len;
        const ch = if (at_end) @as(u8, 0) else args_str[i];

        if (ch == '(' or ch == '[' or ch == '{') {
            depth += 1;
        } else if (ch == ')' or ch == ']' or ch == '}') {
            if (depth > 0) depth -= 1;
        }

        if ((ch == ',' and depth == 0) or at_end) {
            const arg = std.mem.trim(u8, args_str[start..i], &[_]u8{ ' ', '\t' });
            if (arg.len > 0 and count < MAX_ARGS) {
                if (parseOneArg(arg)) |c| {
                    buf[count] = c;
                    count += 1;
                }
            }
            start = i + 1;
        }
    }

    if (count == 0) return null;

    // Return a slice backed by static storage (lives as long as the pattern source string)
    // We need to copy into persistent storage — use a comptime-sized array trick
    const result = std.heap.page_allocator.alloc(ArgConstraint, count) catch return null;
    @memcpy(result, buf[0..count]);
    return result;
}

/// Parse a single argument token into an ArgConstraint.
fn parseOneArg(arg: []const u8) ?ArgConstraint {
    // "..." → ellipsis
    if (std.mem.eql(u8, arg, "...")) {
        return .{ .kind = .ellipsis };
    }

    // f"..." → string_template
    if (arg.len >= 4 and arg[0] == 'f' and arg[1] == '"' and arg[arg.len - 1] == '"') {
        return .{ .kind = .string_template };
    }

    // "..." (literal pattern) → any_string
    if (arg.len >= 5 and arg[0] == '"' and std.mem.eql(u8, arg, "\"...\"")) {
        return .{ .kind = .any_string };
    }

    // "value" → exact_string
    if (arg.len >= 2 and arg[0] == '"' and arg[arg.len - 1] == '"') {
        return .{ .kind = .exact_string, .value = arg[1 .. arg.len - 1] };
    }

    // keyword=value → keyword constraint
    if (std.mem.indexOfScalar(u8, arg, '=')) |eq_idx| {
        if (eq_idx > 0 and eq_idx + 1 < arg.len) {
            // Check it's not ==
            if (eq_idx + 1 < arg.len and arg[eq_idx + 1] == '=') return null;
            const key = std.mem.trim(u8, arg[0..eq_idx], &[_]u8{ ' ', '\t' });
            const val = std.mem.trim(u8, arg[eq_idx + 1 ..], &[_]u8{ ' ', '\t' });
            if (key.len > 0 and val.len > 0) {
                return .{
                    .kind = .identifier_value,
                    .keyword_name = key,
                    .value = val,
                };
            }
        }
    }

    // Bare identifier (True, False, None)
    if (arg.len > 0 and isIdentChar(arg[0])) {
        return .{ .kind = .identifier_value, .value = arg };
    }

    return null;
}

fn isIdentChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
}

fn detectAssignment(src: []const u8) bool {
    // Look for "=" that's not "==" and not inside parens
    var depth: u32 = 0;
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        if (src[i] == '(') {
            depth += 1;
        } else if (src[i] == ')') {
            if (depth > 0) depth -= 1;
        } else if (src[i] == '=' and depth == 0) {
            // Not ==
            if (i + 1 < src.len and src[i + 1] == '=') {
                i += 1;
                continue;
            }
            // Not preceded by ! < > (!=, <=, >=)
            if (i > 0 and (src[i - 1] == '!' or src[i - 1] == '<' or src[i - 1] == '>')) continue;
            return true;
        }
    }
    return false;
}

const MemberCallParts = struct { object: []const u8, method: []const u8 };

fn detectMemberCall(src: []const u8) ?MemberCallParts {
    // "subprocess.call(...)" → object="subprocess", method="call"
    const paren_idx = std.mem.indexOfScalar(u8, src, '(') orelse return null;
    const before_paren = src[0..paren_idx];
    const dot_idx = std.mem.lastIndexOfScalar(u8, before_paren, '.') orelse return null;
    const object = before_paren[0..dot_idx];
    const method = before_paren[dot_idx + 1 ..];
    if (object.len == 0 or method.len == 0) return null;
    // Verify object is an identifier (no special chars)
    if (object[0] == '$' or object[0] == '"') return null;
    return .{ .object = object, .method = method };
}

fn detectCall(src: []const u8) ?[]const u8 {
    // "exec(...)" → "exec"
    const paren_idx = std.mem.indexOfScalar(u8, src, '(') orelse return null;
    const callee = std.mem.trim(u8, src[0..paren_idx], &[_]u8{ ' ', '\t' });
    if (callee.len == 0) return null;
    // Must be a simple identifier (no dots, no $)
    for (callee) |c| {
        if (c == '.' or c == '$' or c == ' ') return null;
    }
    return callee;
}

// ── Prefilter Extraction ──

pub fn extractPrefilter(pattern: CompiledPattern, allocator: std.mem.Allocator) !PrefilterReq {
    var kinds = std.ArrayList(zir.Kind).init(allocator);
    var atoms = std.ArrayList([]const u8).init(allocator);

    switch (pattern) {
        .call => |p| {
            try kinds.append(.call);
            try atoms.append(p.callee);
        },
        .assignment => |_| {
            try kinds.append(.assignment);
        },
        .member_call => |p| {
            try kinds.append(.call);
            try kinds.append(.member_access);
            try atoms.append(p.object);
            try atoms.append(p.method);
        },
        .call_with_args => |p| {
            try kinds.append(.call);
            try atoms.append(p.callee);
        },
        .member_call_with_args => |p| {
            try kinds.append(.call);
            try kinds.append(.member_access);
            try atoms.append(p.object);
            try atoms.append(p.method);
        },
    }

    return .{
        .required_kinds = try kinds.toOwnedSlice(),
        .required_atoms = try atoms.toOwnedSlice(),
    };
}

// ── Convenience ──

pub fn compileRules(rules: []const Rule, allocator: std.mem.Allocator) ![]CompiledRule {
    var compiled = std.ArrayList(CompiledRule).init(allocator);

    for (rules) |r| {
        const pattern = compilePattern(r.pattern_source) catch |err| {
            switch (err) {
                CompileError.UnsupportedPattern => continue, // skip unsupported patterns
                else => return err,
            }
        };
        const prefilter = try extractPrefilter(pattern, allocator);

        // Auto-infer tier if not explicitly set
        var effective_rule = r;
        if (r.tier == 0) {
            switch (pattern) {
                .assignment => |ap| {
                    if (ap.rhs_literal_kind != null) effective_rule.tier = 1;
                },
                .call_with_args, .member_call_with_args => effective_rule.tier = 1,
                else => {},
            }
        }

        try compiled.append(.{
            .rule = effective_rule,
            .pattern = pattern,
            .prefilter = prefilter,
        });
    }

    return compiled.toOwnedSlice();
}
