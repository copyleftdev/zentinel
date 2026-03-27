/// Matcher — runs compiled rules against ZIR trees, produces findings.
const std = @import("std");
const zir = @import("zir");
const rule = @import("rule");

// ── Types ──

pub const FileSignature = struct {
    identifiers: std.StringHashMap(void),
    kinds: std.AutoHashMap(zir.Kind, void),

    pub fn init(allocator: std.mem.Allocator) FileSignature {
        return .{
            .identifiers = std.StringHashMap(void).init(allocator),
            .kinds = std.AutoHashMap(zir.Kind, void).init(allocator),
        };
    }

    pub fn deinit(self: *FileSignature) void {
        self.identifiers.deinit();
        self.kinds.deinit();
    }
};

pub const Finding = struct {
    rule_id: []const u8,
    message: []const u8,
    severity: rule.Severity,
    node_id: zir.NodeId,
    span: zir.Span,
};

// ── File Signature ──

pub fn buildSignature(tree: *const zir.ZirTree, allocator: std.mem.Allocator) !FileSignature {
    var sig = FileSignature.init(allocator);
    for (tree.nodes.items) |node| {
        try sig.kinds.put(node.kind, {});
        if (node.atom) |aid| {
            try sig.identifiers.put(tree.atoms.get(aid), {});
        }
    }
    return sig;
}

// ── Prefilter Check ──

fn passesPrefilter(sig: *const FileSignature, prefilter: rule.PrefilterReq) bool {
    for (prefilter.required_kinds) |k| {
        if (!sig.kinds.contains(k)) return false;
    }
    for (prefilter.required_atoms) |a| {
        if (!sig.identifiers.contains(a)) return false;
    }
    return true;
}

fn languageMatches(compiled: rule.CompiledRule, lang: []const u8) bool {
    for (compiled.rule.languages) |l| {
        if (std.mem.eql(u8, l, lang)) return true;
    }
    return false;
}

// ── Main Match Entry Point ──

pub fn matchRules(
    tree: *const zir.ZirTree,
    compiled_rules: []const rule.CompiledRule,
    lang: []const u8,
    allocator: std.mem.Allocator,
) ![]Finding {
    var findings = std.ArrayList(Finding).init(allocator);

    var sig = try buildSignature(tree, allocator);
    defer sig.deinit();

    for (compiled_rules) |cr| {
        if (!languageMatches(cr, lang)) continue;
        if (!passesPrefilter(&sig, cr.prefilter)) continue;

        switch (cr.pattern) {
            .call => |p| try matchCall(tree, &cr, p, &findings),
            .assignment => |p| try matchAssignment(tree, &cr, p, &findings),
            .member_call => |p| try matchMemberCall(tree, &cr, p, &findings),
        }
    }

    return findings.toOwnedSlice();
}

// ── Pattern-Specific Matchers ──

fn matchCall(
    tree: *const zir.ZirTree,
    cr: *const rule.CompiledRule,
    pattern: rule.CallPattern,
    findings: *std.ArrayList(Finding),
) !void {
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.kind != .call) continue;

        // Check if any child identifier matches the callee name
        if (findCalleeInChildren(tree, @intCast(idx), pattern.callee)) {
            try findings.append(.{
                .rule_id = cr.rule.id,
                .message = cr.rule.message,
                .severity = cr.rule.severity,
                .node_id = @intCast(idx),
                .span = node.span,
            });
        }
    }
}

fn matchAssignment(
    tree: *const zir.ZirTree,
    cr: *const rule.CompiledRule,
    pattern: rule.AssignmentPattern,
    findings: *std.ArrayList(Finding),
) !void {
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.kind != .assignment) continue;

        // For $KEY = "..." pattern: find assignment nodes that have
        // an identifier child and a literal child (at any depth within)
        const has_identifier = hasDescendantKind(tree, @intCast(idx), .identifier, 2);
        const has_literal = hasDescendantKind(tree, @intCast(idx), .literal, 3);

        const lhs_ok = !pattern.lhs_is_metavar or has_identifier;
        const rhs_ok = !pattern.rhs_is_string_literal or has_literal;

        if (lhs_ok and rhs_ok and has_identifier and has_literal) {
            // Avoid duplicate findings from nested assignment nodes (JS lexical_declaration > variable_declarator)
            if (node.parent) |pid| {
                if (tree.nodes.items[pid].kind == .assignment) continue;
            }
            try findings.append(.{
                .rule_id = cr.rule.id,
                .message = cr.rule.message,
                .severity = cr.rule.severity,
                .node_id = @intCast(idx),
                .span = node.span,
            });
        }
    }
}

fn matchMemberCall(
    tree: *const zir.ZirTree,
    cr: *const rule.CompiledRule,
    pattern: rule.MemberCallPattern,
    findings: *std.ArrayList(Finding),
) !void {
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.kind != .call) continue;

        // Find a member_access child that contains both object and method identifiers
        if (findMemberCallMatch(tree, @intCast(idx), pattern.object, pattern.method)) {
            try findings.append(.{
                .rule_id = cr.rule.id,
                .message = cr.rule.message,
                .severity = cr.rule.severity,
                .node_id = @intCast(idx),
                .span = node.span,
            });
        }
    }
}

// ── Helper Functions ──

fn findCalleeInChildren(tree: *const zir.ZirTree, parent_id: zir.NodeId, callee_name: []const u8) bool {
    for (tree.nodes.items) |node| {
        if (node.parent) |pid| {
            if (pid == parent_id and node.kind == .identifier) {
                if (node.atom) |aid| {
                    if (std.mem.eql(u8, tree.atoms.get(aid), callee_name)) return true;
                }
            }
        }
    }
    return false;
}

fn findMemberCallMatch(tree: *const zir.ZirTree, call_id: zir.NodeId, object_name: []const u8, method_name: []const u8) bool {
    // Look for a member_access child of the call
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.parent) |pid| {
            if (pid == call_id and node.kind == .member_access) {
                // Check if this member_access contains both object and method identifiers
                var found_object = false;
                var found_method = false;
                for (tree.nodes.items) |grandchild| {
                    if (grandchild.parent) |gpid| {
                        if (gpid == @as(zir.NodeId, @intCast(idx)) and grandchild.kind == .identifier) {
                            if (grandchild.atom) |aid| {
                                const name = tree.atoms.get(aid);
                                if (std.mem.eql(u8, name, object_name)) found_object = true;
                                if (std.mem.eql(u8, name, method_name)) found_method = true;
                            }
                        }
                    }
                }
                if (found_object and found_method) return true;
            }
        }
    }
    return false;
}

/// Check if a node has a descendant of the given kind within max_depth levels.
fn hasDescendantKind(tree: *const zir.ZirTree, parent_id: zir.NodeId, kind: zir.Kind, max_depth: u32) bool {
    return hasDescendantKindInner(tree, parent_id, kind, max_depth, 0);
}

fn hasDescendantKindInner(tree: *const zir.ZirTree, parent_id: zir.NodeId, kind: zir.Kind, max_depth: u32, depth: u32) bool {
    if (depth >= max_depth) return false;
    for (tree.nodes.items) |node| {
        if (node.parent) |pid| {
            if (pid == parent_id) {
                if (node.kind == kind) return true;
            }
        }
    }
    // Recurse into children
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.parent) |pid| {
            if (pid == parent_id) {
                if (hasDescendantKindInner(tree, @intCast(idx), kind, max_depth, depth + 1)) return true;
            }
        }
    }
    return false;
}
