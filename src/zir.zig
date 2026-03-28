/// ZIR — Zentinel Intermediate Representation
/// A unified, language-agnostic AST for semantic analysis.
const std = @import("std");

/// Sub-classification for literal nodes — what type of value.
/// Packed into upper 4 bits of Node.flags (bits 4–7).
pub const LiteralKind = enum(u4) {
    string, // "...", '...' (includes raw/byte strings)
    number_int, // 42, 0xFF
    number_float, // 3.14, 1e10
    boolean, // true, false, True, False
    null_value, // null, None, undefined
    regex, // /pattern/ (JS)
    collection, // [], {}, ()
    unknown, // could not classify
};

/// Normalized node kinds — language-agnostic.
pub const Kind = enum(u8) {
    module, // top-level / program
    function, // function / method declaration
    call, // function/method call
    identifier, // name reference
    literal, // string, number, bool, null
    assignment, // lhs = rhs
    import, // import / require
    member_access, // a.b / a->b
    control_flow, // if / for / while / match
    return_stmt, // return
    binary_op, // a + b, a && b
    unary_op, // !a, -a
    block, // { ... } / indented block
    parameter, // function parameter
    argument, // call argument
    class, // class / struct
    attribute, // decorator / annotation
    comment, // comment
    string_template, // f-string / template literal
    expression_stmt, // expression used as statement
    unknown, // unmapped node
};

pub const Span = struct {
    start_byte: u32,
    end_byte: u32,
    start_row: u32,
    start_col: u32,
    end_row: u32,
    end_col: u32,
};

pub const NodeId = u32;
pub const AtomId = u32;

pub const Node = struct {
    kind: Kind,
    span: Span,
    flags: u32 = 0,
    children: []NodeId,
    atom: ?AtomId, // interned string (identifier name, literal value)
    parent: ?NodeId,

    // Flags (bits 0–2)
    pub const FLAG_ERROR = 1 << 0; // node or ancestor had parse error
    pub const FLAG_MISSING = 1 << 1; // tree-sitter inserted a missing node
    pub const FLAG_NAMED = 1 << 2; // tree-sitter named node

    // LiteralKind is packed into bits 4–7 of flags
    pub const LITERAL_KIND_SHIFT = 4;
    pub const LITERAL_KIND_MASK: u32 = 0xF0;

    /// Returns the literal sub-type, or null if this node is not a literal.
    pub fn literalKind(self: *const Node) ?LiteralKind {
        if (self.kind != .literal) return null;
        return @enumFromInt(@as(u4, @intCast((self.flags & LITERAL_KIND_MASK) >> LITERAL_KIND_SHIFT)));
    }
};

/// Interned string table for atoms (identifiers, literals).
pub const AtomTable = struct {
    strings: std.ArrayList([]const u8),
    index: std.StringHashMap(AtomId),

    pub fn init(allocator: std.mem.Allocator) AtomTable {
        return .{
            .strings = std.ArrayList([]const u8).init(allocator),
            .index = std.StringHashMap(AtomId).init(allocator),
        };
    }

    pub fn deinit(self: *AtomTable) void {
        self.strings.deinit();
        self.index.deinit();
    }

    pub fn intern(self: *AtomTable, s: []const u8) !AtomId {
        if (self.index.get(s)) |id| return id;
        const id: AtomId = @intCast(self.strings.items.len);
        try self.strings.append(s);
        try self.index.put(s, id);
        return id;
    }

    pub fn get(self: *const AtomTable, id: AtomId) []const u8 {
        return self.strings.items[id];
    }
};

/// A complete ZIR tree: nodes + atoms.
pub const ZirTree = struct {
    nodes: std.ArrayList(Node),
    atoms: AtomTable,
    allocator: std.mem.Allocator,
    source_lang: []const u8,

    pub fn init(allocator: std.mem.Allocator, lang: []const u8) ZirTree {
        return .{
            .nodes = std.ArrayList(Node).init(allocator),
            .atoms = AtomTable.init(allocator),
            .allocator = allocator,
            .source_lang = lang,
        };
    }

    pub fn deinit(self: *ZirTree) void {
        for (self.nodes.items) |node| {
            self.allocator.free(node.children);
        }
        self.nodes.deinit();
        self.atoms.deinit();
    }

    pub fn addNode(self: *ZirTree, kind: Kind, span: Span, atom: ?AtomId, parent: ?NodeId, children: []const NodeId, flags: u32) !NodeId {
        const id: NodeId = @intCast(self.nodes.items.len);
        const owned_children = try self.allocator.alloc(NodeId, children.len);
        @memcpy(owned_children, children);
        try self.nodes.append(.{
            .kind = kind,
            .span = span,
            .flags = flags,
            .children = owned_children,
            .atom = atom,
            .parent = parent,
        });
        return id;
    }

    pub fn getNode(self: *const ZirTree, id: NodeId) *const Node {
        return &self.nodes.items[id];
    }

    /// Count nodes of a specific kind.
    pub fn countKind(self: *const ZirTree, kind: Kind) usize {
        var count: usize = 0;
        for (self.nodes.items) |node| {
            if (node.kind == kind) count += 1;
        }
        return count;
    }

    /// Print the tree for debugging.
    pub fn dump(self: *const ZirTree, writer: anytype) !void {
        for (self.nodes.items, 0..) |node, i| {
            const indent: usize = blk: {
                var depth: usize = 0;
                var p = node.parent;
                while (p) |pid| {
                    depth += 1;
                    p = self.nodes.items[pid].parent;
                }
                break :blk depth;
            };
            for (0..indent) |_| try writer.writeAll("  ");
            try writer.print("[{d}] {s}", .{ i, @tagName(node.kind) });
            if (node.atom) |aid| {
                try writer.print(" \"{s}\"", .{self.atoms.get(aid)});
            }
            if (node.flags & Node.FLAG_ERROR != 0) {
                try writer.writeAll(" [ERROR]");
            }
            try writer.print(" ({d}:{d}-{d}:{d})\n", .{
                node.span.start_row,
                node.span.start_col,
                node.span.end_row,
                node.span.end_col,
            });
        }
    }
};
