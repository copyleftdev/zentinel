/// Zig bindings for tree-sitter C API.
/// Wraps the raw C interface into idiomatic Zig types.
const std = @import("std");

// ── Raw C bindings ──────────────────────────────────────────────────
pub const c = @cImport({
    @cInclude("tree_sitter/api.h");
});

// Language symbols (defined in the compiled grammar .c files)
pub extern fn tree_sitter_python() *c.TSLanguage;
pub extern fn tree_sitter_javascript() *c.TSLanguage;

// ── High-level wrappers ─────────────────────────────────────────────

pub const Language = enum {
    python,
    javascript,

    pub fn tsLanguage(self: Language) *c.TSLanguage {
        return switch (self) {
            .python => tree_sitter_python(),
            .javascript => tree_sitter_javascript(),
        };
    }
};

pub const Parser = struct {
    raw: *c.TSParser,

    pub fn init() !Parser {
        const p = c.ts_parser_new() orelse return error.ParserCreationFailed;
        return .{ .raw = p };
    }

    pub fn deinit(self: *Parser) void {
        c.ts_parser_delete(self.raw);
    }

    pub fn setLanguage(self: *Parser, lang: Language) !void {
        if (!c.ts_parser_set_language(self.raw, lang.tsLanguage())) {
            return error.LanguageVersionMismatch;
        }
    }

    pub fn parse(self: *Parser, source: []const u8) !Tree {
        const tree = c.ts_parser_parse_string(
            self.raw,
            null,
            source.ptr,
            @intCast(source.len),
        ) orelse return error.ParseFailed;
        return .{ .raw = tree, .source = source };
    }
};

pub const Tree = struct {
    raw: *c.TSTree,
    source: []const u8,

    pub fn deinit(self: *Tree) void {
        c.ts_tree_delete(self.raw);
    }

    pub fn rootNode(self: *const Tree) Node {
        return .{ .raw = c.ts_tree_root_node(self.raw), .source = self.source };
    }
};

pub const Node = struct {
    raw: c.TSNode,
    source: []const u8,

    pub fn nodeType(self: *const Node) []const u8 {
        const ptr = c.ts_node_type(self.raw);
        return std.mem.span(ptr);
    }

    pub fn startByte(self: *const Node) u32 {
        return c.ts_node_start_byte(self.raw);
    }

    pub fn endByte(self: *const Node) u32 {
        return c.ts_node_end_byte(self.raw);
    }

    pub fn startPoint(self: *const Node) c.TSPoint {
        return c.ts_node_start_point(self.raw);
    }

    pub fn endPoint(self: *const Node) c.TSPoint {
        return c.ts_node_end_point(self.raw);
    }

    pub fn text(self: *const Node) []const u8 {
        return self.source[self.startByte()..self.endByte()];
    }

    pub fn childCount(self: *const Node) u32 {
        return c.ts_node_child_count(self.raw);
    }

    pub fn namedChildCount(self: *const Node) u32 {
        return c.ts_node_named_child_count(self.raw);
    }

    pub fn child(self: *const Node, index: u32) ?Node {
        const c_node = c.ts_node_child(self.raw, index);
        if (c.ts_node_is_null(c_node)) return null;
        return .{ .raw = c_node, .source = self.source };
    }

    pub fn namedChild(self: *const Node, index: u32) ?Node {
        const c_node = c.ts_node_named_child(self.raw, index);
        if (c.ts_node_is_null(c_node)) return null;
        return .{ .raw = c_node, .source = self.source };
    }

    pub fn isNamed(self: *const Node) bool {
        return c.ts_node_is_named(self.raw);
    }

    pub fn isMissing(self: *const Node) bool {
        return c.ts_node_is_missing(self.raw);
    }

    pub fn hasError(self: *const Node) bool {
        return c.ts_node_has_error(self.raw);
    }

    pub fn parent(self: *const Node) ?Node {
        const p = c.ts_node_parent(self.raw);
        if (c.ts_node_is_null(p)) return null;
        return .{ .raw = p, .source = self.source };
    }

    /// Walk all named descendants depth-first, calling visitor for each.
    pub fn walk(self: *const Node, ctx: anytype, visitor: fn (@TypeOf(ctx), *const Node, u32) void, depth: u32) void {
        visitor(ctx, self, depth);
        var i: u32 = 0;
        while (i < self.childCount()) : (i += 1) {
            if (self.child(i)) |ch| {
                ch.walk(ctx, visitor, depth + 1);
            }
        }
    }
};

/// Cursor-based tree walker for efficient traversal.
pub const Cursor = struct {
    raw: c.TSTreeCursor,
    source: []const u8,

    pub fn init(node: Node) Cursor {
        return .{
            .raw = c.ts_tree_cursor_new(node.raw),
            .source = node.source,
        };
    }

    pub fn deinit(self: *Cursor) void {
        c.ts_tree_cursor_delete(&self.raw);
    }

    pub fn currentNode(self: *const Cursor) Node {
        return .{
            .raw = c.ts_tree_cursor_current_node(&self.raw),
            .source = self.source,
        };
    }

    pub fn gotoFirstChild(self: *Cursor) bool {
        return c.ts_tree_cursor_goto_first_child(&self.raw);
    }

    pub fn gotoNextSibling(self: *Cursor) bool {
        return c.ts_tree_cursor_goto_next_sibling(&self.raw);
    }

    pub fn gotoParent(self: *Cursor) bool {
        return c.ts_tree_cursor_goto_parent(&self.raw);
    }
};
