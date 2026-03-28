/// Matcher — runs compiled rules against ZIR trees, produces findings.
const std = @import("std");
const zir = @import("zir");
const rule = @import("rule");
const secrets = @import("secrets");

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
        if (cr.rule.tier >= 2) continue; // Tier 2+ handled by taint engine
        if (!languageMatches(cr, lang)) continue;
        if (!passesPrefilter(&sig, cr.prefilter)) continue;

        switch (cr.pattern) {
            .call => |p| try matchCall(tree, &cr, p, &findings),
            .assignment => |p| try matchAssignment(tree, &cr, p, &findings),
            .member_call => |p| try matchMemberCall(tree, &cr, p, &findings),
            .call_with_args => |p| try matchCallWithArgs(tree, &cr, p, &findings),
            .member_call_with_args => |p| try matchMemberCallWithArgs(tree, &cr, p, &findings),
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
            // Tier 1: check literal sub-type if required
            if (pattern.rhs_literal_kind) |required_lk| {
                if (!hasDescendantLiteralKind(tree, @intCast(idx), required_lk, 3)) continue;
            }

            // Tier 1: check LHS name hint — identifier must look like a secret
            if (pattern.lhs_name_hint != null) {
                if (!lhsMatchesSecretHint(tree, @intCast(idx))) continue;
            }

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

/// Tier 1: Check if a node has a descendant literal of the given LiteralKind within max_depth.
fn hasDescendantLiteralKind(tree: *const zir.ZirTree, parent_id: zir.NodeId, lk: zir.LiteralKind, max_depth: u32) bool {
    return hasDescendantLiteralKindInner(tree, parent_id, lk, max_depth, 0);
}

fn hasDescendantLiteralKindInner(tree: *const zir.ZirTree, parent_id: zir.NodeId, lk: zir.LiteralKind, max_depth: u32, depth: u32) bool {
    if (depth >= max_depth) return false;
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.parent) |pid| {
            if (pid == parent_id) {
                if (node.kind == .literal) {
                    if (node.literalKind()) |k| {
                        if (k == lk) return true;
                    }
                }
                if (hasDescendantLiteralKindInner(tree, @intCast(idx), lk, max_depth, depth + 1)) return true;
            }
        }
    }
    return false;
}

/// Two-gate secret detection: name must contain keyword AND value must look like a secret.
fn lhsMatchesSecretHint(tree: *const zir.ZirTree, assign_id: zir.NodeId) bool {
    var lhs_name: ?[]const u8 = null;
    var rhs_value: ?[]const u8 = null;

    // Search depth 2 for LHS name and RHS value
    for (tree.nodes.items, 0..) |child, child_idx| {
        if (child.parent) |pid| {
            if (pid == assign_id) {
                // LHS: first identifier
                if (child.kind == .identifier and lhs_name == null) {
                    if (child.atom) |aid| lhs_name = tree.atoms.get(aid);
                }
                // RHS: literal value
                if (child.kind == .literal) {
                    if (child.atom) |aid| rhs_value = tree.atoms.get(aid);
                }
                // Grandchildren (JS: lexical_declaration → variable_declarator → ...)
                for (tree.nodes.items) |gc| {
                    if (gc.parent) |gpid| {
                        if (gpid == @as(zir.NodeId, @intCast(child_idx))) {
                            if (gc.kind == .identifier and lhs_name == null) {
                                if (gc.atom) |aid| lhs_name = tree.atoms.get(aid);
                            }
                            if (gc.kind == .literal and rhs_value == null) {
                                if (gc.atom) |aid| rhs_value = tree.atoms.get(aid);
                            }
                        }
                    }
                }
            }
        }
    }

    const name = lhs_name orelse return false;
    const value = rhs_value orelse return false;
    return secrets.looksLikeSecret(name, value);
}

// ── Tier 1: Argument-Constrained Matchers ──

fn matchCallWithArgs(
    tree: *const zir.ZirTree,
    cr: *const rule.CompiledRule,
    pattern: rule.CallWithArgsPattern,
    findings: *std.ArrayList(Finding),
) !void {
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.kind != .call) continue;
        if (!findCalleeInChildren(tree, @intCast(idx), pattern.callee)) continue;
        if (checkArgConstraints(tree, @intCast(idx), pattern.constraints)) {
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

fn matchMemberCallWithArgs(
    tree: *const zir.ZirTree,
    cr: *const rule.CompiledRule,
    pattern: rule.MemberCallWithArgsPattern,
    findings: *std.ArrayList(Finding),
) !void {
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.kind != .call) continue;
        if (!findMemberCallMatch(tree, @intCast(idx), pattern.object, pattern.method)) continue;
        if (checkArgConstraints(tree, @intCast(idx), pattern.constraints)) {
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

/// Check argument constraints against a call node's argument children.
fn checkArgConstraints(tree: *const zir.ZirTree, call_id: zir.NodeId, constraints: []const rule.ArgConstraint) bool {
    // Collect argument child nodes (children of .argument nodes under the call)
    var arg_nodes: [16]zir.NodeId = undefined;
    var arg_count: usize = 0;

    // Find argument list node (direct .argument child of call)
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.parent) |pid| {
            if (pid == call_id and node.kind == .argument) {
                // Collect children of the argument list as individual args
                for (tree.nodes.items, 0..) |arg_child, arg_idx| {
                    if (arg_child.parent) |apid| {
                        if (apid == @as(zir.NodeId, @intCast(idx)) and arg_count < 16) {
                            arg_nodes[arg_count] = @intCast(arg_idx);
                            arg_count += 1;
                        }
                    }
                }
                break;
            }
        }
    }

    // Check each non-ellipsis constraint
    for (constraints) |c| {
        switch (c.kind) {
            .ellipsis => continue, // ... matches anything
            .any_string => {
                // At least one arg must be a string literal
                var found = false;
                for (arg_nodes[0..arg_count]) |nid| {
                    if (nodeIsStringLiteral(tree, nid)) {
                        found = true;
                        break;
                    }
                }
                if (!found) return false;
            },
            .exact_string => {
                // At least one arg must be a literal with matching value
                const target = c.value orelse continue;
                var found = false;
                for (arg_nodes[0..arg_count]) |nid| {
                    if (nodeHasLiteralValue(tree, nid, target)) {
                        found = true;
                        break;
                    }
                }
                if (!found) return false;
            },
            .string_template => {
                // At least one arg must be a string_template
                var found = false;
                for (arg_nodes[0..arg_count]) |nid| {
                    if (nodeIsKindRecursive(tree, nid, .string_template)) {
                        found = true;
                        break;
                    }
                }
                if (!found) return false;
            },
            .identifier_value => {
                if (c.keyword_name) |kw_name| {
                    // Keyword arg: look for argument node with matching key=value
                    if (!hasKeywordArg(tree, call_id, kw_name, c.value)) return false;
                } else {
                    // Positional identifier value
                    const target = c.value orelse continue;
                    var found = false;
                    for (arg_nodes[0..arg_count]) |nid| {
                        if (nodeHasIdentifierValue(tree, nid, target)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) return false;
                }
            },
        }
    }
    return true;
}

fn nodeIsStringLiteral(tree: *const zir.ZirTree, nid: zir.NodeId) bool {
    const node = tree.nodes.items[nid];
    if (node.kind == .literal) {
        if (node.literalKind()) |lk| return lk == .string;
    }
    return false;
}

fn nodeHasLiteralValue(tree: *const zir.ZirTree, nid: zir.NodeId, target: []const u8) bool {
    const node = tree.nodes.items[nid];
    if (node.kind == .literal) {
        if (node.atom) |aid| {
            const atom_str = tree.atoms.get(aid);
            // Compare with and without quotes (atoms may include quotes for strings)
            if (std.mem.eql(u8, atom_str, target)) return true;
            // Strip surrounding quotes if present
            if (atom_str.len >= 2 and (atom_str[0] == '"' or atom_str[0] == '\'')) {
                if (std.mem.eql(u8, atom_str[1 .. atom_str.len - 1], target)) return true;
            }
        }
    }
    // Check children (literal may be nested, e.g. inside string node)
    for (tree.nodes.items, 0..) |child, child_idx| {
        if (child.parent) |pid| {
            if (pid == nid and child.kind == .literal) {
                if (child.atom) |aid| {
                    const atom_str = tree.atoms.get(aid);
                    if (std.mem.eql(u8, atom_str, target)) return true;
                    if (atom_str.len >= 2 and (atom_str[0] == '"' or atom_str[0] == '\'')) {
                        if (std.mem.eql(u8, atom_str[1 .. atom_str.len - 1], target)) return true;
                    }
                }
                _ = child_idx;
            }
        }
    }
    return false;
}

fn nodeIsKindRecursive(tree: *const zir.ZirTree, nid: zir.NodeId, kind: zir.Kind) bool {
    if (tree.nodes.items[nid].kind == kind) return true;
    // Check children
    for (tree.nodes.items) |child| {
        if (child.parent) |pid| {
            if (pid == nid and child.kind == kind) return true;
        }
    }
    return false;
}

fn nodeHasIdentifierValue(tree: *const zir.ZirTree, nid: zir.NodeId, target: []const u8) bool {
    const node = tree.nodes.items[nid];
    if (node.kind == .identifier) {
        if (node.atom) |aid| {
            if (std.mem.eql(u8, tree.atoms.get(aid), target)) return true;
        }
    }
    if (node.kind == .literal) {
        if (node.atom) |aid| {
            if (std.mem.eql(u8, tree.atoms.get(aid), target)) return true;
        }
    }
    return false;
}

fn hasKeywordArg(tree: *const zir.ZirTree, call_id: zir.NodeId, keyword_name: []const u8, expected_value: ?[]const u8) bool {
    // Python keyword_argument nodes become .argument in ZIR
    // Structure: call → argument_list(.argument) → keyword_argument(.argument) → [identifier(key), value]
    // We need to find an .argument node under the call that has:
    //   1. An identifier child matching keyword_name
    //   2. A sibling child matching expected_value (literal or identifier)
    for (tree.nodes.items, 0..) |node, idx| {
        if (node.parent == null) continue;
        // Walk all argument-like nodes in the call subtree
        if (node.kind != .argument) continue;

        // Check if this argument (or its ancestor) is under the call
        if (!isDescendantOf(tree, @intCast(idx), call_id, 4)) continue;

        var found_key = false;
        var found_value = false;

        for (tree.nodes.items) |child| {
            if (child.parent) |cpid| {
                if (cpid == @as(zir.NodeId, @intCast(idx))) {
                    if (child.kind == .identifier) {
                        if (child.atom) |aid| {
                            if (std.mem.eql(u8, tree.atoms.get(aid), keyword_name)) found_key = true;
                        }
                    }
                    if (expected_value) |ev| {
                        if (child.kind == .identifier or child.kind == .literal) {
                            if (child.atom) |aid| {
                                if (std.mem.eql(u8, tree.atoms.get(aid), ev)) found_value = true;
                            }
                        }
                    } else {
                        found_value = true; // no value constraint
                    }
                }
            }
        }
        if (found_key and found_value) return true;
    }
    return false;
}

fn isDescendantOf(tree: *const zir.ZirTree, node_id: zir.NodeId, ancestor_id: zir.NodeId, max_depth: u32) bool {
    var current = node_id;
    var depth: u32 = 0;
    while (depth < max_depth) : (depth += 1) {
        if (tree.nodes.items[current].parent) |pid| {
            if (pid == ancestor_id) return true;
            current = pid;
        } else return false;
    }
    return false;
}
