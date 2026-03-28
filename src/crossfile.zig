/// Cross-file analysis — Tier 3 data flow tracking across module boundaries.
///
/// Two-pass architecture:
///   Pass 1: Parse all files, extract exports (top-level functions) and imports
///   Pass 2: For each import called with tainted args, run taint analysis on callee
const std = @import("std");
const zir = @import("zir");
const rule = @import("rule");
const matcher = @import("matcher");
const fast_matcher = @import("fast_matcher");
const taint = @import("taint");

// ── Types ──

pub const ModuleExport = struct {
    function_name: []const u8,
    func_node_id: zir.NodeId,
};

pub const ModuleImport = struct {
    local_name: []const u8,
    source_module: []const u8,
};

pub const StoredFile = struct {
    tree: zir.ZirTree,
    ci: fast_matcher.ChildIndex,
    lang: []const u8,
    exports: []ModuleExport,
    imports: []ModuleImport,
};

pub const CrossFileIndex = struct {
    files: std.StringHashMap(StoredFile),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) CrossFileIndex {
        return .{
            .files = std.StringHashMap(StoredFile).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *CrossFileIndex) void {
        var it = self.files.iterator();
        while (it.next()) |entry| {
            var sf = entry.value_ptr;
            sf.ci.deinit(self.allocator);
            sf.tree.deinit();
            self.allocator.free(sf.exports);
            self.allocator.free(sf.imports);
        }
        self.files.deinit();
    }
};

// ── Export/Import Extraction ──

/// Extract top-level function exports from a ZIR tree.
pub fn extractExports(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    allocator: std.mem.Allocator,
) ![]ModuleExport {
    var exports = std.ArrayList(ModuleExport).init(allocator);

    // Find the module (root) node
    if (tree.nodes.items.len == 0) return exports.toOwnedSlice();
    const root_id: zir.NodeId = 0;
    if (tree.nodes.items[root_id].kind != .module) return exports.toOwnedSlice();

    // Top-level functions are direct children of module (or children of expression_stmt under module)
    for (ci.children(root_id)) |child_id| {
        const child = tree.nodes.items[child_id];
        if (child.kind == .function) {
            if (getFuncName(tree, ci, child_id)) |name| {
                try exports.append(.{ .function_name = name, .func_node_id = child_id });
            }
        }
        // Also check expression_stmt children (some languages wrap functions)
        if (child.kind == .expression_stmt or child.kind == .assignment) {
            for (ci.children(child_id)) |gc_id| {
                if (tree.nodes.items[gc_id].kind == .function) {
                    if (getFuncName(tree, ci, gc_id)) |name| {
                        try exports.append(.{ .function_name = name, .func_node_id = gc_id });
                    }
                }
            }
        }
    }

    return exports.toOwnedSlice();
}

/// Extract imports from a ZIR tree.
pub fn extractImports(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    allocator: std.mem.Allocator,
) ![]ModuleImport {
    var imports = std.ArrayList(ModuleImport).init(allocator);

    for (tree.nodes.items, 0..) |node, idx| {
        if (node.kind != .import) continue;

        // Collect identifier descendants of the import node (up to depth 3)
        // Identifiers may be nested under dotted_name (.unknown) or import_spec nodes
        const children = ci.children(@intCast(idx));
        var names: [8][]const u8 = undefined;
        var name_count: usize = 0;

        for (children) |child_id| {
            collectIdentifiers(tree, ci, child_id, &names, &name_count, 3);
        }

        // For "from module import name" patterns:
        // First identifier is typically the module, rest are imported names
        if (name_count >= 2) {
            const module_name = names[0];
            for (names[1..name_count]) |imported_name| {
                try imports.append(.{
                    .local_name = imported_name,
                    .source_module = module_name,
                });
            }
        }
    }

    return imports.toOwnedSlice();
}

// ── Module Resolution ──

/// Resolve a module name to a file path in the scanned file set.
pub fn resolveModule(module_name: []const u8, file_paths: []const []const u8) ?[]const u8 {
    for (file_paths) |fp| {
        const basename = std.fs.path.stem(fp);
        if (std.mem.eql(u8, basename, module_name)) return fp;
    }
    return null;
}

// ── Cross-File Taint Analysis ──

/// Run cross-file taint analysis for a specific file.
/// Checks if any imported function is called with tainted data from this file,
/// and if so, runs taint analysis on the imported function in its source file.
pub fn analyzeCrossFile(
    index: *const CrossFileIndex,
    file_path: []const u8,
    sinks: []const taint.SinkSpec,
    file_paths: []const []const u8,
    allocator: std.mem.Allocator,
) ![]matcher.Finding {
    var findings = std.ArrayList(matcher.Finding).init(allocator);

    const caller_file = index.files.get(file_path) orelse return findings.toOwnedSlice();

    // For each import in this file
    for (caller_file.imports) |imp| {
        // Resolve the source module to a file
        const target_path = resolveModule(imp.source_module, file_paths) orelse continue;
        const target_file = index.files.get(target_path) orelse continue;

        // Find the exported function in the target file
        var target_func_id: ?zir.NodeId = null;
        for (target_file.exports) |exp| {
            if (std.mem.eql(u8, exp.function_name, imp.local_name)) {
                target_func_id = exp.func_node_id;
                break;
            }
        }
        if (target_func_id == null) continue;

        // Run Tier 2 on the caller file to find tainted calls to this import
        const tainted_args = try findTaintedCallArgs(
            &caller_file.tree,
            &caller_file.ci,
            imp.local_name,
            allocator,
        );
        defer allocator.free(tainted_args);

        if (tainted_args.len == 0) continue;

        // Run taint analysis on the target function with seeded params
        const target_findings = try taint.analyzeFunctionWithSeededParams(
            &target_file.tree,
            &target_file.ci,
            target_func_id.?,
            tainted_args,
            sinks,
            allocator,
        );
        defer allocator.free(target_findings);

        // Re-attribute findings to the call site in the caller file
        for (target_findings) |tf| {
            // Find the call site in caller file for attribution
            const call_span = findCallSite(&caller_file.tree, &caller_file.ci, imp.local_name);
            try findings.append(.{
                .rule_id = tf.rule_id,
                .message = tf.message,
                .severity = tf.severity,
                .node_id = tf.node_id,
                .span = call_span orelse tf.span,
            });
        }
    }

    return findings.toOwnedSlice();
}

// ── Helpers ──

/// Recursively collect identifier names from a node and its descendants.
fn collectIdentifiers(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    node_id: zir.NodeId,
    names: *[8][]const u8,
    name_count: *usize,
    max_depth: u32,
) void {
    if (max_depth == 0 or name_count.* >= 8) return;
    const node = tree.nodes.items[node_id];
    if (node.kind == .identifier) {
        if (node.atom) |aid| {
            names[name_count.*] = tree.atoms.get(aid);
            name_count.* += 1;
        }
    }
    for (ci.children(node_id)) |child_id| {
        collectIdentifiers(tree, ci, child_id, names, name_count, max_depth - 1);
    }
}

fn getFuncName(tree: *const zir.ZirTree, ci: *const fast_matcher.ChildIndex, func_id: zir.NodeId) ?[]const u8 {
    for (ci.children(func_id)) |child_id| {
        const child = tree.nodes.items[child_id];
        if (child.kind == .identifier) {
            if (child.atom) |aid| return tree.atoms.get(aid);
        }
    }
    return null;
}

/// Find which argument positions are tainted when calling a specific function.
/// Runs Tier 2 taint analysis on all functions in the file, looking for calls
/// to `callee_name` with tainted arguments.
fn findTaintedCallArgs(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    callee_name: []const u8,
    allocator: std.mem.Allocator,
) ![]u32 {
    var tainted_positions = std.ArrayList(u32).init(allocator);

    // For each function in the file, check if it calls callee_name with tainted args
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.kind != .function) continue;

        // Build per-function taint map (seed all params as tainted, like Tier 2)
        var taint_map = std.AutoHashMap(zir.AtomId, taint.TaintState).init(allocator);
        defer taint_map.deinit();

        for (ci.children(@intCast(idx))) |child_id| {
            if (tree.nodes.items[child_id].kind == .parameter) {
                for (ci.children(child_id)) |pc_id| {
                    if (tree.nodes.items[pc_id].kind == .identifier) {
                        if (tree.nodes.items[pc_id].atom) |aid| {
                            try taint_map.put(aid, .{
                                .source_node = pc_id,
                                .reason = .parameter,
                                .source_atom = null,
                            });
                        }
                    }
                }
            }
        }

        // Forward pass: propagate taint through assignments
        const func_end = findSubtreeEnd(ci, @intCast(idx));
        var nid: zir.NodeId = @as(zir.NodeId, @intCast(idx)) + 1;
        while (nid < func_end) : (nid += 1) {
            const n = tree.nodes.items[nid];
            if (!isDescendantOf(tree, nid, @intCast(idx))) continue;

            if (n.kind == .assignment) {
                // Simple propagation: if RHS has tainted identifier, taint LHS
                const children = ci.children(nid);
                var lhs_atom: ?zir.AtomId = null;
                var rhs_tainted = false;
                var first_id_seen = false;
                for (children) |cid| {
                    const c = tree.nodes.items[cid];
                    if (c.kind == .identifier and c.atom != null) {
                        if (!first_id_seen) {
                            lhs_atom = c.atom;
                            first_id_seen = true;
                        } else {
                            if (taint_map.contains(c.atom.?)) rhs_tainted = true;
                        }
                    }
                    // Check subtree for tainted identifiers
                    if (c.kind != .identifier) {
                        if (findTaintedInSubtree(tree, ci, cid, &taint_map, 4) != null) rhs_tainted = true;
                    }
                }
                if (lhs_atom != null and rhs_tainted) {
                    try taint_map.put(lhs_atom.?, .{
                        .source_node = nid,
                        .reason = .assignment_direct,
                        .source_atom = null,
                    });
                }
            }

            // Check for calls to callee_name with tainted args
            if (n.kind == .call) {
                var is_target_call = false;
                for (ci.children(nid)) |cid| {
                    const c = tree.nodes.items[cid];
                    if (c.kind == .identifier) {
                        if (c.atom) |aid| {
                            if (std.mem.eql(u8, tree.atoms.get(aid), callee_name)) {
                                is_target_call = true;
                            }
                        }
                    }
                }

                if (is_target_call) {
                    // Check which argument positions are tainted
                    var arg_pos: u32 = 0;
                    for (ci.children(nid)) |cid| {
                        if (tree.nodes.items[cid].kind == .argument) {
                            for (ci.children(cid)) |arg_child_id| {
                                if (findTaintedInSubtree(tree, ci, arg_child_id, &taint_map, 3) != null) {
                                    // Check if already in list
                                    var found = false;
                                    for (tainted_positions.items) |existing| {
                                        if (existing == arg_pos) {
                                            found = true;
                                            break;
                                        }
                                    }
                                    if (!found) try tainted_positions.append(arg_pos);
                                }
                                arg_pos += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    return tainted_positions.toOwnedSlice();
}

fn findTaintedInSubtree(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    node_id: zir.NodeId,
    taint_map: *const std.AutoHashMap(zir.AtomId, taint.TaintState),
    max_depth: u32,
) ?zir.AtomId {
    if (max_depth == 0) return null;
    const node = tree.nodes.items[node_id];
    if (node.kind == .identifier) {
        if (node.atom) |aid| {
            if (taint_map.contains(aid)) return aid;
        }
    }
    for (ci.children(node_id)) |child_id| {
        if (tree.nodes.items[child_id].kind == .identifier) {
            if (tree.nodes.items[child_id].atom) |aid| {
                if (taint_map.contains(aid)) return aid;
            }
        }
        if (findTaintedInSubtree(tree, ci, child_id, taint_map, max_depth - 1)) |aid| return aid;
    }
    return null;
}

fn findSubtreeEnd(ci: *const fast_matcher.ChildIndex, root_id: zir.NodeId) zir.NodeId {
    var max_id = root_id;
    var stack: [64]zir.NodeId = undefined;
    var stack_len: usize = 1;
    stack[0] = root_id;
    while (stack_len > 0) {
        stack_len -= 1;
        const nid = stack[stack_len];
        if (nid > max_id) max_id = nid;
        for (ci.children(nid)) |child_id| {
            if (stack_len < 64) {
                stack[stack_len] = child_id;
                stack_len += 1;
            }
        }
    }
    return max_id + 1;
}

fn isDescendantOf(tree: *const zir.ZirTree, node_id: zir.NodeId, ancestor_id: zir.NodeId) bool {
    var current = node_id;
    var depth: u32 = 0;
    while (depth < 20) : (depth += 1) {
        if (tree.nodes.items[current].parent) |pid| {
            if (pid == ancestor_id) return true;
            current = pid;
        } else return false;
    }
    return false;
}

/// Find the span of a call to `callee_name` in the tree (for finding attribution).
fn findCallSite(tree: *const zir.ZirTree, ci: *const fast_matcher.ChildIndex, callee_name: []const u8) ?zir.Span {
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.kind != .call) continue;
        for (ci.children(@intCast(idx))) |child_id| {
            const child = tree.nodes.items[child_id];
            if (child.kind == .identifier) {
                if (child.atom) |aid| {
                    if (std.mem.eql(u8, tree.atoms.get(aid), callee_name)) {
                        return node.span;
                    }
                }
            }
        }
    }
    return null;
}
