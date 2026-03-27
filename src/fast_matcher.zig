/// Fast matcher — indexed, single-pass rule matching with O(1) child lookups.
///
/// Two-level indexing:
///   1. RuleIndex: atom hash → rules (dispatch table, built once per scan)
///   2. ChildIndex: parent_id → [child_ids] (adjacency list, built once per file)
///
/// SIMD-friendly: atom hashes packed into vectors for parallel comparison.
const std = @import("std");
const zir = @import("zir");
const rule = @import("rule");
const matcher = @import("matcher");

// ── Child Index (parent → children adjacency list) ──

/// Precomputed parent→children index for O(1) child lookups.
/// Replaces all O(N) linear scans over nodes looking for parent matches.
pub const ChildIndex = struct {
    /// For each node, the start offset into `all_children`.
    offsets: []u32,
    /// For each node, the number of children.
    lengths: []u32,
    /// Flat packed array of all child IDs, grouped by parent.
    all_children: []zir.NodeId,

    pub fn build(tree: *const zir.ZirTree, allocator: std.mem.Allocator) !ChildIndex {
        const n = tree.nodes.items.len;

        // Count children per parent
        var counts = try allocator.alloc(u32, n);
        defer allocator.free(counts);
        @memset(counts, 0);

        for (tree.nodes.items) |node| {
            if (node.parent) |pid| {
                if (pid < n) counts[pid] += 1;
            }
        }

        // Compute offsets (prefix sum)
        var offsets = try allocator.alloc(u32, n);
        var total: u32 = 0;
        for (0..n) |i| {
            offsets[i] = total;
            total += counts[i];
        }

        // Fill children array
        var all_children = try allocator.alloc(zir.NodeId, total);
        // Use a write cursor per parent
        var cursors = try allocator.alloc(u32, n);
        defer allocator.free(cursors);
        @memcpy(cursors, offsets);

        for (tree.nodes.items, 0..) |node, idx| {
            if (node.parent) |pid| {
                if (pid < n) {
                    all_children[cursors[pid]] = @intCast(idx);
                    cursors[pid] += 1;
                }
            }
        }

        // Copy counts into owned lengths
        const lengths = try allocator.alloc(u32, n);
        @memcpy(lengths, counts);

        return .{
            .offsets = offsets,
            .lengths = lengths,
            .all_children = all_children,
        };
    }

    pub fn deinit(self: *ChildIndex, allocator: std.mem.Allocator) void {
        allocator.free(self.offsets);
        allocator.free(self.lengths);
        allocator.free(self.all_children);
    }

    /// Get the children of a node as a slice.
    pub inline fn children(self: *const ChildIndex, node_id: zir.NodeId) []const zir.NodeId {
        const off = self.offsets[node_id];
        const len = self.lengths[node_id];
        return self.all_children[off..][0..len];
    }
};

// ── Rule Index ──

pub const RuleIndex = struct {
    call_map: std.AutoHashMap(u64, std.ArrayList(IndexEntry)),
    member_call_map: std.AutoHashMap(u64, std.ArrayList(IndexEntry)),
    assignment_rules: std.ArrayList(IndexEntry),
    compiled: []const rule.CompiledRule,
    call_hashes: []u64,
    call_entries: []IndexEntry,
    allocator: std.mem.Allocator,

    pub const IndexEntry = struct {
        rule_idx: u32,
        cr: rule.CompiledRule,
    };

    pub fn build(compiled_rules: []const rule.CompiledRule, allocator: std.mem.Allocator) !RuleIndex {
        var call_map = std.AutoHashMap(u64, std.ArrayList(IndexEntry)).init(allocator);
        var member_call_map = std.AutoHashMap(u64, std.ArrayList(IndexEntry)).init(allocator);
        var assignment_rules = std.ArrayList(IndexEntry).init(allocator);
        var call_hashes_list = std.ArrayList(u64).init(allocator);
        var call_entries_list = std.ArrayList(IndexEntry).init(allocator);

        for (compiled_rules, 0..) |cr, i| {
            const entry = IndexEntry{ .rule_idx = @intCast(i), .cr = cr };
            switch (cr.pattern) {
                .call => |p| {
                    const h = atomHash(p.callee);
                    const gop = try call_map.getOrPut(h);
                    if (!gop.found_existing) gop.value_ptr.* = std.ArrayList(IndexEntry).init(allocator);
                    try gop.value_ptr.append(entry);
                    try call_hashes_list.append(h);
                    try call_entries_list.append(entry);
                },
                .member_call => |p| {
                    const h = atomHash(p.method);
                    const gop = try member_call_map.getOrPut(h);
                    if (!gop.found_existing) gop.value_ptr.* = std.ArrayList(IndexEntry).init(allocator);
                    try gop.value_ptr.append(entry);
                },
                .assignment => try assignment_rules.append(entry),
            }
        }

        return .{
            .call_map = call_map,
            .member_call_map = member_call_map,
            .assignment_rules = assignment_rules,
            .compiled = compiled_rules,
            .call_hashes = try call_hashes_list.toOwnedSlice(),
            .call_entries = try call_entries_list.toOwnedSlice(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RuleIndex) void {
        var it = self.call_map.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit();
        self.call_map.deinit();
        var it2 = self.member_call_map.iterator();
        while (it2.next()) |entry| entry.value_ptr.deinit();
        self.member_call_map.deinit();
        self.assignment_rules.deinit();
        self.allocator.free(self.call_hashes);
        self.allocator.free(self.call_entries);
    }
};

// ── SIMD ──

pub fn atomHash(s: []const u8) u64 {
    return std.hash.Wyhash.hash(0, s);
}

pub fn simdFindHash(needle_hash: u64, haystack: []const u64) ?usize {
    const VEC_LEN = 4;
    const Vec = @Vector(VEC_LEN, u64);
    const needle_vec: Vec = @splat(needle_hash);

    var i: usize = 0;
    while (i + VEC_LEN <= haystack.len) : (i += VEC_LEN) {
        const chunk: Vec = haystack[i..][0..VEC_LEN].*;
        const cmp = chunk == needle_vec;
        if (@reduce(.Or, cmp)) {
            const mask: [VEC_LEN]bool = cmp;
            for (mask, 0..) |m, j| {
                if (m) return i + j;
            }
        }
    }
    while (i < haystack.len) : (i += 1) {
        if (haystack[i] == needle_hash) return i;
    }
    return null;
}

// ── Single-Pass Matcher ──

/// Match all rules, building the ChildIndex internally. Convenience wrapper.
pub fn matchIndexed(
    tree: *const zir.ZirTree,
    index: *const RuleIndex,
    lang: []const u8,
    allocator: std.mem.Allocator,
) ![]matcher.Finding {
    var ci = try ChildIndex.build(tree, allocator);
    defer ci.deinit(allocator);
    return matchWithIndex(tree, index, &ci, lang, allocator);
}

/// Match all rules using a pre-built ChildIndex. Use this when scanning
/// the same tree with multiple rule sets, or when benchmarking match-only time.
pub fn matchWithIndex(
    tree: *const zir.ZirTree,
    index: *const RuleIndex,
    ci: *const ChildIndex,
    lang: []const u8,
    allocator: std.mem.Allocator,
) ![]matcher.Finding {
    var findings = std.ArrayList(matcher.Finding).init(allocator);

    for (tree.nodes.items, 0..) |node, idx| {
        const nid: zir.NodeId = @intCast(idx);
        switch (node.kind) {
            .call => {
                const info = findCalleeInfoIndexed(tree, ci, nid);

                // Direct call patterns
                if (info.direct_atom) |atom_str| {
                    const h = atomHash(atom_str);
                    if (index.call_hashes.len > 0) {
                        var search_pos: usize = 0;
                        while (search_pos < index.call_hashes.len) {
                            const match_idx = simdFindHash(h, index.call_hashes[search_pos..]);
                            if (match_idx) |mi| {
                                const abs_idx = search_pos + mi;
                                const entry = index.call_entries[abs_idx];
                                if (std.mem.eql(u8, atom_str, entry.cr.pattern.call.callee)) {
                                    if (languageMatches(entry.cr, lang)) {
                                        try findings.append(.{
                                            .rule_id = entry.cr.rule.id,
                                            .message = entry.cr.rule.message,
                                            .severity = entry.cr.rule.severity,
                                            .node_id = nid,
                                            .span = node.span,
                                        });
                                    }
                                }
                                search_pos = abs_idx + 1;
                            } else break;
                        }
                    }
                }

                // Member call patterns
                for (info.member_atoms[0..info.member_count]) |member_atom| {
                    const mh = atomHash(member_atom);
                    if (index.member_call_map.get(mh)) |entries| {
                        for (entries.items) |entry| {
                            if (languageMatches(entry.cr, lang)) {
                                const mc = entry.cr.pattern.member_call;
                                if (memberCallMatchIndexed(tree, ci, nid, mc.object, mc.method)) {
                                    try findings.append(.{
                                        .rule_id = entry.cr.rule.id,
                                        .message = entry.cr.rule.message,
                                        .severity = entry.cr.rule.severity,
                                        .node_id = nid,
                                        .span = node.span,
                                    });
                                }
                            }
                        }
                    }
                }
            },
            .assignment => {
                for (index.assignment_rules.items) |entry| {
                    if (languageMatches(entry.cr, lang)) {
                        const pattern = entry.cr.pattern.assignment;
                        const has_id = hasDescendantKindIndexed(tree, ci, nid, .identifier, 2);
                        const has_lit = hasDescendantKindIndexed(tree, ci, nid, .literal, 3);

                        if (has_id and has_lit) {
                            if ((!pattern.lhs_is_metavar or has_id) and
                                (!pattern.rhs_is_string_literal or has_lit))
                            {
                                if (node.parent) |pid| {
                                    if (tree.nodes.items[pid].kind == .assignment) continue;
                                }
                                try findings.append(.{
                                    .rule_id = entry.cr.rule.id,
                                    .message = entry.cr.rule.message,
                                    .severity = entry.cr.rule.severity,
                                    .node_id = nid,
                                    .span = node.span,
                                });
                            }
                        }
                    }
                }
            },
            else => {},
        }
    }

    return findings.toOwnedSlice();
}

// ── Indexed Helpers (O(children) instead of O(nodes)) ──

fn languageMatches(cr: rule.CompiledRule, lang: []const u8) bool {
    for (cr.rule.languages) |l| {
        if (std.mem.eql(u8, l, lang)) return true;
    }
    return false;
}

const CalleeInfo = struct {
    direct_atom: ?[]const u8,
    member_atoms: [8][]const u8,
    member_count: u8,
};

fn findCalleeInfoIndexed(tree: *const zir.ZirTree, ci: *const ChildIndex, call_id: zir.NodeId) CalleeInfo {
    var info = CalleeInfo{ .direct_atom = null, .member_atoms = undefined, .member_count = 0 };

    for (ci.children(call_id)) |child_id| {
        const child = tree.nodes.items[child_id];
        if (child.kind == .identifier) {
            if (child.atom) |aid| info.direct_atom = tree.atoms.get(aid);
        } else if (child.kind == .member_access) {
            for (ci.children(child_id)) |gc_id| {
                const gc = tree.nodes.items[gc_id];
                if (gc.kind == .identifier) {
                    if (gc.atom) |aid| {
                        if (info.member_count < 8) {
                            info.member_atoms[info.member_count] = tree.atoms.get(aid);
                            info.member_count += 1;
                        }
                    }
                }
            }
        }
    }
    return info;
}

fn memberCallMatchIndexed(tree: *const zir.ZirTree, ci: *const ChildIndex, call_id: zir.NodeId, object_name: []const u8, method_name: []const u8) bool {
    for (ci.children(call_id)) |child_id| {
        const child = tree.nodes.items[child_id];
        if (child.kind == .member_access) {
            var found_object = false;
            var found_method = false;
            for (ci.children(child_id)) |gc_id| {
                const gc = tree.nodes.items[gc_id];
                if (gc.kind == .identifier) {
                    if (gc.atom) |aid| {
                        const name = tree.atoms.get(aid);
                        if (std.mem.eql(u8, name, object_name)) found_object = true;
                        if (std.mem.eql(u8, name, method_name)) found_method = true;
                    }
                }
            }
            if (found_object and found_method) return true;
        }
    }
    return false;
}

fn hasDescendantKindIndexed(tree: *const zir.ZirTree, ci: *const ChildIndex, parent_id: zir.NodeId, kind: zir.Kind, max_depth: u32) bool {
    return hasDescendantInner(tree, ci, parent_id, kind, max_depth, 0);
}

fn hasDescendantInner(tree: *const zir.ZirTree, ci: *const ChildIndex, parent_id: zir.NodeId, kind: zir.Kind, max_depth: u32, depth: u32) bool {
    if (depth >= max_depth) return false;
    for (ci.children(parent_id)) |child_id| {
        if (tree.nodes.items[child_id].kind == kind) return true;
    }
    for (ci.children(parent_id)) |child_id| {
        if (hasDescendantInner(tree, ci, child_id, kind, max_depth, depth + 1)) return true;
    }
    return false;
}
