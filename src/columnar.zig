/// Columnar ZIR storage — mmap-friendly binary format for cached ZIR trees.
///
/// Format: header + 12 aligned columns + flat children array + atom blob.
/// ~45 bytes/node (vs ~65 AoS). ChildIndex is zero-copy from columns.
///
/// Key operations:
///   serialize:    ZirTree + ChildIndex → binary buffer
///   deserialize:  binary buffer → ColumnarTree
///   toZirTree:    ColumnarTree → ZirTree (for consumer compatibility)
const std = @import("std");
const zir = @import("zir");
const fast_matcher = @import("fast_matcher");
const normalizer = @import("normalizer");

// ── Constants ──

const MAGIC = [4]u8{ 'Z', 'I', 'R', 0x01 };
const FORMAT_VERSION: u32 = 1;
const NULL_SENTINEL: u32 = 0xFFFFFFFF;

// ── Header ──

const Header = extern struct {
    magic: [4]u8,
    format_version: u32,
    normalizer_version: u32,
    node_count: u32,
    total_children: u32,
    atom_blob_size: u32,
    atom_count: u32,
    source_lang_len: u16,
    _pad: u16 = 0,
};

// ── ColumnarTree ──

pub const ColumnarTree = struct {
    kinds: []const u8,
    flags: []const u32,
    atoms: []const u32,
    parents: []const u32,
    child_offsets: []const u32,
    child_counts: []const u32,
    start_bytes: []const u32,
    end_bytes: []const u32,
    start_rows: []const u32,
    start_cols: []const u32,
    end_rows: []const u32,
    end_cols: []const u32,
    all_children: []const u32,
    atom_blob: []const u8,
    node_count: u32,
    atom_count: u32,
    source_lang: []const u8,

    // Backing storage
    data: ?[]align(4) const u8, // mmap'd or allocated backing buffer
    allocator: ?std.mem.Allocator,

    pub fn deinit(self: *ColumnarTree) void {
        if (self.data) |d| {
            if (self.allocator) |alloc| {
                alloc.free(d);
            }
        }
    }

    /// Build a ChildIndex as a zero-copy view over the columnar data.
    pub fn childIndex(self: *const ColumnarTree) fast_matcher.ChildIndex {
        return .{
            .offsets = @constCast(self.child_offsets),
            .lengths = @constCast(self.child_counts),
            .all_children = @constCast(self.all_children),
        };
    }

    /// Resolve an atom offset to a string slice within the atom blob.
    pub fn atomString(self: *const ColumnarTree, offset: u32) ?[]const u8 {
        if (offset == NULL_SENTINEL) return null;
        if (offset + 4 > self.atom_blob.len) return null;
        const len = std.mem.readInt(u32, self.atom_blob[offset..][0..4], .little);
        const start = offset + 4;
        if (start + len > self.atom_blob.len) return null;
        return self.atom_blob[start..][0..len];
    }

    /// Reconstruct a full ZirTree from columnar data (for consumer compatibility).
    pub fn toZirTree(self: *const ColumnarTree, allocator: std.mem.Allocator) !zir.ZirTree {
        var tree = zir.ZirTree.init(allocator, self.source_lang);

        // Rebuild atom table
        var offset: u32 = 0;
        for (0..self.atom_count) |_| {
            if (offset + 4 > self.atom_blob.len) break;
            const len = std.mem.readInt(u32, self.atom_blob[offset..][0..4], .little);
            offset += 4;
            if (offset + len > self.atom_blob.len) break;
            const s = self.atom_blob[offset..][0..len];
            _ = try tree.atoms.intern(s);
            offset += len;
        }

        // Rebuild nodes
        for (0..self.node_count) |i| {
            const atom_off = self.atoms[i];
            var atom_id: ?zir.AtomId = null;
            if (atom_off != NULL_SENTINEL) {
                // Find the atom string and look up its ID
                if (self.atomString(atom_off)) |s| {
                    atom_id = tree.atoms.index.get(s);
                }
            }

            const parent: ?zir.NodeId = if (self.parents[i] == NULL_SENTINEL) null else self.parents[i];

            // Get children for this node
            const c_off = self.child_offsets[i];
            const c_len = self.child_counts[i];
            const children = self.all_children[c_off..][0..c_len];

            const span = zir.Span{
                .start_byte = self.start_bytes[i],
                .end_byte = self.end_bytes[i],
                .start_row = self.start_rows[i],
                .start_col = self.start_cols[i],
                .end_row = self.end_rows[i],
                .end_col = self.end_cols[i],
            };

            _ = try tree.addNode(
                @enumFromInt(self.kinds[i]),
                span,
                atom_id,
                parent,
                children,
                self.flags[i],
            );
        }

        return tree;
    }
};

// ── Serialize ──

/// Serialize a ZirTree + ChildIndex into columnar binary format.
pub fn serialize(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    allocator: std.mem.Allocator,
) ![]u8 {
    const n: u32 = @intCast(tree.nodes.items.len);
    const total_children: u32 = @intCast(ci.all_children.len);

    // Build atom blob: each atom = u32 length + bytes
    var atom_blob = std.ArrayList(u8).init(allocator);
    defer atom_blob.deinit();

    // Map AtomId → byte offset in blob
    var atom_offsets = try allocator.alloc(u32, tree.atoms.strings.items.len);
    defer allocator.free(atom_offsets);

    for (tree.atoms.strings.items, 0..) |s, i| {
        atom_offsets[i] = @intCast(atom_blob.items.len);
        const len: u32 = @intCast(s.len);
        try atom_blob.writer().writeInt(u32, len, .little);
        try atom_blob.appendSlice(s);
    }

    const atom_count: u32 = @intCast(tree.atoms.strings.items.len);
    const atom_blob_size: u32 = @intCast(atom_blob.items.len);
    const lang = tree.source_lang;
    const lang_len: u16 = @intCast(lang.len);

    // Calculate total size
    const header_size = @sizeOf(Header) + lang.len;
    const header_padded = alignUp(header_size, 4);
    const kinds_padded = alignUp(n, 4); // u8[N] padded to 4B

    var total_size: usize = header_padded;
    total_size += kinds_padded; // kinds
    total_size += @as(usize, n) * 4 * 11; // 11 u32 columns
    total_size += @as(usize, total_children) * 4; // all_children
    total_size += atom_blob_size; // atom blob

    var buf = try allocator.alloc(u8, total_size);
    @memset(buf, 0);

    var pos: usize = 0;

    // Write header
    const header = Header{
        .magic = MAGIC,
        .format_version = FORMAT_VERSION,
        .normalizer_version = normalizer.VERSION,
        .node_count = n,
        .total_children = total_children,
        .atom_blob_size = atom_blob_size,
        .atom_count = atom_count,
        .source_lang_len = lang_len,
    };
    @memcpy(buf[pos..][0..@sizeOf(Header)], std.mem.asBytes(&header));
    pos += @sizeOf(Header);
    @memcpy(buf[pos..][0..lang.len], lang);
    pos = header_padded;

    // Write kinds (u8[N], padded)
    for (0..n) |i| {
        buf[pos + i] = @intFromEnum(tree.nodes.items[i].kind);
    }
    pos += kinds_padded;

    // Helper: write u32 column
    const writeU32Col = struct {
        fn f(b: []u8, p: *usize, values: []const u32) void {
            for (values, 0..) |v, i| {
                std.mem.writeInt(u32, b[p.* + i * 4 ..][0..4], v, .little);
            }
            p.* += values.len * 4;
        }
    }.f;

    // Build per-node u32 arrays
    var flags_arr = try allocator.alloc(u32, n);
    defer allocator.free(flags_arr);
    var atoms_arr = try allocator.alloc(u32, n);
    defer allocator.free(atoms_arr);
    var parents_arr = try allocator.alloc(u32, n);
    defer allocator.free(parents_arr);
    var sb = try allocator.alloc(u32, n);
    defer allocator.free(sb);
    var eb = try allocator.alloc(u32, n);
    defer allocator.free(eb);
    var sr = try allocator.alloc(u32, n);
    defer allocator.free(sr);
    var sc = try allocator.alloc(u32, n);
    defer allocator.free(sc);
    var er = try allocator.alloc(u32, n);
    defer allocator.free(er);
    var ec = try allocator.alloc(u32, n);
    defer allocator.free(ec);

    for (tree.nodes.items, 0..) |node, i| {
        flags_arr[i] = node.flags;
        atoms_arr[i] = if (node.atom) |aid| atom_offsets[aid] else NULL_SENTINEL;
        parents_arr[i] = if (node.parent) |pid| pid else NULL_SENTINEL;
        sb[i] = node.span.start_byte;
        eb[i] = node.span.end_byte;
        sr[i] = node.span.start_row;
        sc[i] = node.span.start_col;
        er[i] = node.span.end_row;
        ec[i] = node.span.end_col;
    }

    writeU32Col(buf, &pos, flags_arr);
    writeU32Col(buf, &pos, atoms_arr);
    writeU32Col(buf, &pos, parents_arr);
    writeU32Col(buf, &pos, ci.offsets);
    writeU32Col(buf, &pos, ci.lengths);
    writeU32Col(buf, &pos, sb);
    writeU32Col(buf, &pos, eb);
    writeU32Col(buf, &pos, sr);
    writeU32Col(buf, &pos, sc);
    writeU32Col(buf, &pos, er);
    writeU32Col(buf, &pos, ec);

    // all_children
    for (ci.all_children, 0..) |child_id, i| {
        std.mem.writeInt(u32, buf[pos + i * 4 ..][0..4], child_id, .little);
    }
    pos += total_children * 4;

    // atom blob
    @memcpy(buf[pos..][0..atom_blob_size], atom_blob.items);

    return buf;
}

// ── Deserialize ──

/// Deserialize columnar binary data into a ColumnarTree.
pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !ColumnarTree {
    if (data.len < @sizeOf(Header)) return error.InvalidFormat;

    const header: *const Header = @ptrCast(@alignCast(data.ptr));
    if (!std.mem.eql(u8, &header.magic, &MAGIC)) return error.InvalidMagic;
    if (header.format_version != FORMAT_VERSION) return error.VersionMismatch;
    if (header.normalizer_version != normalizer.VERSION) return error.NormalizerVersionMismatch;

    const n = header.node_count;
    const total_children = header.total_children;
    const atom_blob_size = header.atom_blob_size;
    const lang_len = header.source_lang_len;

    const header_end = @sizeOf(Header);
    const header_padded = alignUp(header_end + lang_len, 4);
    const kinds_padded = alignUp(n, 4);

    // Dupe the backing data so slices remain valid after caller frees input
    const owned = try allocator.alignedAlloc(u8, 4, data.len);
    @memcpy(owned, data);

    // Re-derive all slices from the owned copy at the same offsets
    var pos2: usize = header_padded;
    const o_kinds = owned[pos2..][0..n];
    pos2 += kinds_padded;

    const readOwned = struct {
        fn f(d: []align(4) const u8, p: *usize, count: u32) []const u32 {
            const byte_len = @as(usize, count) * 4;
            const bytes: []align(4) const u8 = @alignCast(d[p.*..][0..byte_len]);
            p.* += byte_len;
            return std.mem.bytesAsSlice(u32, bytes);
        }
    }.f;

    const o_flags = readOwned(owned, &pos2, n);
    const o_atoms = readOwned(owned, &pos2, n);
    const o_parents = readOwned(owned, &pos2, n);
    const o_child_offsets = readOwned(owned, &pos2, n);
    const o_child_counts = readOwned(owned, &pos2, n);
    const o_start_bytes = readOwned(owned, &pos2, n);
    const o_end_bytes = readOwned(owned, &pos2, n);
    const o_start_rows = readOwned(owned, &pos2, n);
    const o_start_cols = readOwned(owned, &pos2, n);
    const o_end_rows = readOwned(owned, &pos2, n);
    const o_end_cols = readOwned(owned, &pos2, n);
    const o_all_children = readOwned(owned, &pos2, total_children);
    const o_atom_blob = owned[pos2..][0..atom_blob_size];
    const o_source_lang = owned[header_end..][0..lang_len];

    return ColumnarTree{
        .kinds = o_kinds,
        .flags = o_flags,
        .atoms = o_atoms,
        .parents = o_parents,
        .child_offsets = o_child_offsets,
        .child_counts = o_child_counts,
        .start_bytes = o_start_bytes,
        .end_bytes = o_end_bytes,
        .start_rows = o_start_rows,
        .start_cols = o_start_cols,
        .end_rows = o_end_rows,
        .end_cols = o_end_cols,
        .all_children = o_all_children,
        .atom_blob = o_atom_blob,
        .node_count = n,
        .atom_count = header.atom_count,
        .source_lang = o_source_lang,
        .data = owned,
        .allocator = allocator,
    };
}

// ── Cache Key ──

/// Compute a content-addressed cache key for ZIR storage.
pub fn zirCacheKey(source: []const u8) u64 {
    var combined: [12]u8 = undefined;
    const src_hash = std.hash.Wyhash.hash(0, source);
    std.mem.writeInt(u64, combined[0..8], src_hash, .little);
    std.mem.writeInt(u32, combined[8..12], normalizer.VERSION, .little);
    return std.hash.Wyhash.hash(0, &combined);
}

/// Format a cache file path for a ZIR key.
pub fn zirCachePath(key: u64, buf: *[256]u8) []const u8 {
    return std.fmt.bufPrint(buf, ".zentinel-cache/{x:0>16}.zir", .{key}) catch buf[0..0];
}

// ── Helpers ──

fn alignUp(val: usize, alignment: usize) usize {
    return (val + alignment - 1) & ~(alignment - 1);
}
