/// Taint analysis — intra-procedural data flow tracking (Tier 2).
///
/// For each function, tracks tainted data from parameters through
/// assignments to dangerous sinks. Single forward pass, no CFG needed.
const std = @import("std");
const zir = @import("zir");
const rule = @import("rule");
const matcher = @import("matcher");
const fast_matcher = @import("fast_matcher");

// ── Types ──

pub const TaintReason = enum {
    parameter, // function parameter (initial source)
    assignment_direct, // x = tainted_var
    assignment_template, // x = f"...{tainted}..."
    assignment_call, // x = func(tainted_arg)
};

pub const TaintState = struct {
    source_node: zir.NodeId,
    reason: TaintReason,
    source_atom: ?zir.AtomId, // atom of the variable that caused taint (for path)
};

// ── Sink specification ──

pub const SinkSpec = struct {
    rule_id: []const u8,
    message: []const u8,
    severity: rule.Severity,
    callee: ?[]const u8, // for direct calls: "exec"
    object: ?[]const u8, // for member calls: "cursor"
    method: ?[]const u8, // for member calls: "execute"
};

// ── Public API ──

/// Run taint analysis on all functions in the tree against the given sinks.
pub fn analyzeTaint(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    sinks: []const SinkSpec,
    lang: []const u8,
    allocator: std.mem.Allocator,
) ![]matcher.Finding {
    _ = lang; // language filtering already done by caller
    var findings = std.ArrayList(matcher.Finding).init(allocator);

    // Find and analyze each function
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.kind == .function) {
            try analyzeFunction(tree, ci, @intCast(idx), sinks, &findings, allocator);
        }
    }

    return findings.toOwnedSlice();
}

/// Extract SinkSpecs from Tier 2 compiled rules.
pub fn extractSinks(compiled_rules: []const rule.CompiledRule, lang: []const u8, allocator: std.mem.Allocator) ![]SinkSpec {
    var sinks = std.ArrayList(SinkSpec).init(allocator);

    for (compiled_rules) |cr| {
        if (cr.rule.tier < 2) continue;

        // Check language match
        var lang_match = false;
        for (cr.rule.languages) |l| {
            if (std.mem.eql(u8, l, lang)) {
                lang_match = true;
                break;
            }
        }
        if (!lang_match) continue;

        switch (cr.pattern) {
            .call => |p| {
                try sinks.append(.{
                    .rule_id = cr.rule.id,
                    .message = cr.rule.message,
                    .severity = cr.rule.severity,
                    .callee = p.callee,
                    .object = null,
                    .method = null,
                });
            },
            .member_call => |p| {
                try sinks.append(.{
                    .rule_id = cr.rule.id,
                    .message = cr.rule.message,
                    .severity = cr.rule.severity,
                    .callee = null,
                    .object = p.object,
                    .method = p.method,
                });
            },
            else => {},
        }
    }

    return sinks.toOwnedSlice();
}

/// Extract SinkSpecs from rules at a specific tier or higher.
pub fn extractSinksAtTier(compiled_rules: []const rule.CompiledRule, min_tier: u8, allocator: std.mem.Allocator) ![]SinkSpec {
    var sinks = std.ArrayList(SinkSpec).init(allocator);

    for (compiled_rules) |cr| {
        if (cr.rule.tier < min_tier) continue;

        switch (cr.pattern) {
            .call => |p| {
                try sinks.append(.{
                    .rule_id = cr.rule.id,
                    .message = cr.rule.message,
                    .severity = cr.rule.severity,
                    .callee = p.callee,
                    .object = null,
                    .method = null,
                });
            },
            .member_call => |p| {
                try sinks.append(.{
                    .rule_id = cr.rule.id,
                    .message = cr.rule.message,
                    .severity = cr.rule.severity,
                    .callee = null,
                    .object = p.object,
                    .method = p.method,
                });
            },
            else => {},
        }
    }

    return sinks.toOwnedSlice();
}

// ── Per-Function Analysis ──

fn analyzeFunction(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    func_id: zir.NodeId,
    sinks: []const SinkSpec,
    findings: *std.ArrayList(matcher.Finding),
    allocator: std.mem.Allocator,
) !void {
    // Taint map: AtomId → TaintState
    var taint_map = std.AutoHashMap(zir.AtomId, TaintState).init(allocator);
    defer taint_map.deinit();

    // Phase 1: Seed taint from function parameters
    for (ci.children(func_id)) |child_id| {
        if (tree.nodes.items[child_id].kind == .parameter) {
            try seedParameterTaint(tree, ci, child_id, &taint_map);
        }
    }

    // Phase 2: Forward pass — collect all descendants, process in order
    // Nodes are stored in pre-order (source order), so iterating by NodeId
    // within the function's subtree gives us the correct forward order.
    const func_start = func_id;
    const func_end = findSubtreeEnd(tree, ci, func_id);

    var nid: zir.NodeId = func_start + 1;
    while (nid < func_end) : (nid += 1) {
        const node = tree.nodes.items[nid];

        // Only process nodes inside this function (check ancestry)
        if (!isDescendantOfCached(tree, nid, func_id, func_end)) continue;

        switch (node.kind) {
            .assignment => try processAssignment(tree, ci, nid, &taint_map),
            .call => try checkSink(tree, ci, nid, &taint_map, sinks, findings),
            else => {},
        }
    }
}

/// Analyze a specific function with only certain parameters seeded as tainted.
/// Used by cross-file analysis (Tier 3) to seed taint from call arguments.
pub fn analyzeFunctionWithSeededParams(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    func_id: zir.NodeId,
    tainted_param_indices: []const u32,
    sinks: []const SinkSpec,
    allocator: std.mem.Allocator,
) ![]matcher.Finding {
    var findings = std.ArrayList(matcher.Finding).init(allocator);

    var taint_map = std.AutoHashMap(zir.AtomId, TaintState).init(allocator);
    defer taint_map.deinit();

    // Seed only specified parameters
    var param_idx: u32 = 0;
    for (ci.children(func_id)) |child_id| {
        if (tree.nodes.items[child_id].kind == .parameter) {
            for (tainted_param_indices) |ti| {
                if (ti == param_idx) {
                    try seedParameterTaint(tree, ci, child_id, &taint_map);
                    break;
                }
            }
            param_idx += 1;
        }
    }

    // Forward pass (same as analyzeFunction)
    const func_end = findSubtreeEnd(tree, ci, func_id);
    var nid: zir.NodeId = func_id + 1;
    while (nid < func_end) : (nid += 1) {
        if (!isDescendantOfCached(tree, nid, func_id, func_end)) {
            continue;
        }
        switch (tree.nodes.items[nid].kind) {
            .assignment => try processAssignment(tree, ci, nid, &taint_map),
            .call => try checkSink(tree, ci, nid, &taint_map, sinks, &findings),
            else => {},
        }
    }

    return findings.toOwnedSlice();
}

/// Get parameter names for a function node (in order).
pub fn getFunctionParamNames(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    func_id: zir.NodeId,
    allocator: std.mem.Allocator,
) ![]const []const u8 {
    var names = std.ArrayList([]const u8).init(allocator);
    for (ci.children(func_id)) |child_id| {
        if (tree.nodes.items[child_id].kind == .parameter) {
            for (ci.children(child_id)) |pc_id| {
                if (tree.nodes.items[pc_id].kind == .identifier) {
                    if (tree.nodes.items[pc_id].atom) |aid| {
                        try names.append(tree.atoms.get(aid));
                    }
                }
            }
        }
    }
    return names.toOwnedSlice();
}

/// Seed taint from a parameter node's identifier children.
fn seedParameterTaint(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    param_id: zir.NodeId,
    taint_map: *std.AutoHashMap(zir.AtomId, TaintState),
) !void {
    for (ci.children(param_id)) |child_id| {
        const child = tree.nodes.items[child_id];
        if (child.kind == .identifier) {
            if (child.atom) |aid| {
                try taint_map.put(aid, .{
                    .source_node = child_id,
                    .reason = .parameter,
                    .source_atom = null,
                });
            }
        }
    }
    // Also check the parameter node itself (some languages put atom directly on parameter)
    const param = tree.nodes.items[param_id];
    if (param.atom) |aid| {
        if (!taint_map.contains(aid)) {
            try taint_map.put(aid, .{
                .source_node = param_id,
                .reason = .parameter,
                .source_atom = null,
            });
        }
    }
}

/// Process an assignment: if RHS contains tainted identifiers, mark LHS as tainted.
fn processAssignment(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    assign_id: zir.NodeId,
    taint_map: *std.AutoHashMap(zir.AtomId, TaintState),
) !void {
    const children = ci.children(assign_id);
    if (children.len == 0) return;

    // Find LHS identifier (first identifier child)
    var lhs_atom: ?zir.AtomId = null;
    for (children) |child_id| {
        const child = tree.nodes.items[child_id];
        if (child.kind == .identifier and child.atom != null) {
            lhs_atom = child.atom;
            break;
        }
    }

    if (lhs_atom == null) return;

    // Check RHS for taint: scan all non-LHS children and their descendants
    var found_taint = false;
    var taint_reason: TaintReason = .assignment_direct;
    var source_atom: ?zir.AtomId = null;
    var first_lhs_seen = false;

    for (children) |child_id| {
        const child = tree.nodes.items[child_id];

        // Skip the LHS identifier (first identifier with matching atom)
        if (!first_lhs_seen and child.kind == .identifier and child.atom != null and child.atom.? == lhs_atom.?) {
            first_lhs_seen = true;
            continue;
        }

        // Check this child and its descendants for tainted identifiers
        if (findTaintedIdentifier(tree, ci, child_id, taint_map, 4)) |tainted_atom| {
            found_taint = true;
            source_atom = tainted_atom;

            // Determine reason based on child type
            if (child.kind == .string_template) {
                taint_reason = .assignment_template;
            } else if (child.kind == .call) {
                taint_reason = .assignment_call;
            } else {
                taint_reason = .assignment_direct;
            }
            break;
        }

        // Also check if child is a string_template or call containing taint
        if (child.kind == .string_template or child.kind == .call) {
            if (findTaintedInSubtree(tree, ci, child_id, taint_map, 4)) |tainted_atom| {
                found_taint = true;
                source_atom = tainted_atom;
                taint_reason = if (child.kind == .string_template) .assignment_template else .assignment_call;
                break;
            }
        }
    }

    if (found_taint) {
        try taint_map.put(lhs_atom.?, .{
            .source_node = assign_id,
            .reason = taint_reason,
            .source_atom = source_atom,
        });
    }
}

/// Check if a call node matches any sink and has tainted arguments.
fn checkSink(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    call_id: zir.NodeId,
    taint_map: *const std.AutoHashMap(zir.AtomId, TaintState),
    sinks: []const SinkSpec,
    findings: *std.ArrayList(matcher.Finding),
) !void {
    // Extract callee info
    var direct_callee: ?[]const u8 = null;
    var member_object: ?[]const u8 = null;
    var member_method: ?[]const u8 = null;

    for (ci.children(call_id)) |child_id| {
        const child = tree.nodes.items[child_id];
        if (child.kind == .identifier) {
            if (child.atom) |aid| direct_callee = tree.atoms.get(aid);
        } else if (child.kind == .member_access) {
            for (ci.children(child_id)) |gc_id| {
                const gc = tree.nodes.items[gc_id];
                if (gc.kind == .identifier) {
                    if (gc.atom) |aid| {
                        const name = tree.atoms.get(aid);
                        if (member_object == null) {
                            member_object = name;
                        } else {
                            member_method = name;
                        }
                    }
                }
            }
        }
    }

    // Match against sinks
    for (sinks) |sink| {
        const matches = blk: {
            if (sink.callee) |callee| {
                if (direct_callee) |dc| {
                    if (std.mem.eql(u8, dc, callee)) break :blk true;
                }
            }
            if (sink.object != null and sink.method != null) {
                if (member_object) |obj| {
                    if (member_method) |meth| {
                        if (std.mem.eql(u8, obj, sink.object.?) and std.mem.eql(u8, meth, sink.method.?)) break :blk true;
                    }
                }
            }
            break :blk false;
        };

        if (!matches) continue;

        // Check if any argument is tainted
        if (findTaintedArgument(tree, ci, call_id, taint_map)) {
            try findings.append(.{
                .rule_id = sink.rule_id,
                .message = sink.message,
                .severity = sink.severity,
                .node_id = call_id,
                .span = tree.nodes.items[call_id].span,
            });
        }
    }
}

// ── Helpers ──

/// Check if any argument of a call is tainted.
fn findTaintedArgument(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    call_id: zir.NodeId,
    taint_map: *const std.AutoHashMap(zir.AtomId, TaintState),
) bool {
    for (ci.children(call_id)) |child_id| {
        if (tree.nodes.items[child_id].kind == .argument) {
            // Check children of argument list
            if (findTaintedInSubtree(tree, ci, child_id, taint_map, 3) != null) return true;
        }
        // Also check direct identifier arguments (some call structures)
        if (tree.nodes.items[child_id].kind == .identifier) {
            if (tree.nodes.items[child_id].atom) |aid| {
                if (taint_map.contains(aid)) return true;
            }
        }
    }
    return false;
}

/// Find a tainted identifier in a node or its direct children.
fn findTaintedIdentifier(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    node_id: zir.NodeId,
    taint_map: *const std.AutoHashMap(zir.AtomId, TaintState),
    max_depth: u32,
) ?zir.AtomId {
    return findTaintedInSubtree(tree, ci, node_id, taint_map, max_depth);
}

/// Recursively search a subtree for any tainted identifier.
fn findTaintedInSubtree(
    tree: *const zir.ZirTree,
    ci: *const fast_matcher.ChildIndex,
    node_id: zir.NodeId,
    taint_map: *const std.AutoHashMap(zir.AtomId, TaintState),
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
        const child = tree.nodes.items[child_id];
        if (child.kind == .identifier) {
            if (child.atom) |aid| {
                if (taint_map.contains(aid)) return aid;
            }
        }
        if (findTaintedInSubtree(tree, ci, child_id, taint_map, max_depth - 1)) |aid| {
            return aid;
        }
    }

    return null;
}

/// Find the end of a subtree rooted at `root_id` (exclusive upper bound of NodeIds).
fn findSubtreeEnd(_: *const zir.ZirTree, ci: *const fast_matcher.ChildIndex, root_id: zir.NodeId) zir.NodeId {
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

/// Check if node_id is a descendant of ancestor_id, with bounded search.
fn isDescendantOfCached(tree: *const zir.ZirTree, node_id: zir.NodeId, ancestor_id: zir.NodeId, bound: zir.NodeId) bool {
    _ = bound;
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
