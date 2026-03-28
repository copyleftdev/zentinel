/// Normalizer — CST → ZIR conversion.
/// Maps tree-sitter concrete syntax trees into Zentinel's language-agnostic
/// intermediate representation (ZIR).
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");

/// Map a tree-sitter node type string to a ZIR Kind for the given language.
pub fn mapKind(node_type: []const u8, lang: ts.Language) zir.Kind {
    return switch (lang) {
        .python => mapKindPython(node_type),
        .javascript => mapKindJavaScript(node_type),
    };
}

fn mapKindPython(t: []const u8) zir.Kind {
    // Module
    if (eq(t, "module")) return .module;

    // Declarations
    if (eq(t, "function_definition")) return .function;
    if (eq(t, "lambda")) return .function;
    if (eq(t, "class_definition")) return .class;

    // Expressions
    if (eq(t, "call")) return .call;
    if (eq(t, "identifier")) return .identifier;
    if (eq(t, "attribute")) return .member_access;

    // Literals
    if (eq(t, "string")) return .literal;
    if (eq(t, "integer")) return .literal;
    if (eq(t, "float")) return .literal;
    if (eq(t, "true") or eq(t, "false") or eq(t, "none")) return .literal;
    if (eq(t, "list")) return .literal;
    if (eq(t, "dictionary")) return .literal;
    if (eq(t, "tuple")) return .literal;

    // Assignment
    if (eq(t, "assignment")) return .assignment;
    if (eq(t, "augmented_assignment")) return .assignment;

    // Imports
    if (eq(t, "import_statement") or eq(t, "import_from_statement")) return .import;

    // Control flow
    if (eq(t, "if_statement") or eq(t, "for_statement") or eq(t, "while_statement")) return .control_flow;
    if (eq(t, "conditional_expression")) return .control_flow;
    if (eq(t, "try_statement")) return .control_flow;
    if (eq(t, "with_statement")) return .control_flow;
    if (eq(t, "raise_statement")) return .control_flow;

    // Operators
    if (eq(t, "binary_operator")) return .binary_op;
    if (eq(t, "boolean_operator")) return .binary_op;
    if (eq(t, "comparison_operator")) return .binary_op;
    if (eq(t, "unary_operator")) return .unary_op;
    if (eq(t, "not_operator")) return .unary_op;

    // Structural
    if (eq(t, "return_statement")) return .return_stmt;
    if (eq(t, "block")) return .block;
    if (eq(t, "parameters")) return .parameter;
    if (eq(t, "default_parameter")) return .parameter;
    if (eq(t, "argument_list")) return .argument;
    if (eq(t, "keyword_argument")) return .argument;
    if (eq(t, "decorator")) return .attribute;
    if (eq(t, "comment")) return .comment;
    if (eq(t, "expression_statement")) return .expression_stmt;
    if (eq(t, "formatted_string") or eq(t, "f_string")) return .string_template;

    return .unknown;
}

fn mapKindJavaScript(t: []const u8) zir.Kind {
    // Module
    if (eq(t, "program")) return .module;

    // Declarations
    if (eq(t, "function_declaration") or eq(t, "method_definition") or eq(t, "arrow_function")) return .function;
    if (eq(t, "class_declaration") or eq(t, "class")) return .class;

    // Expressions
    if (eq(t, "call_expression")) return .call;
    if (eq(t, "new_expression")) return .call;
    if (eq(t, "identifier")) return .identifier;
    if (eq(t, "property_identifier")) return .identifier;
    if (eq(t, "shorthand_property_identifier")) return .identifier;
    if (eq(t, "this")) return .identifier;
    if (eq(t, "member_expression")) return .member_access;
    if (eq(t, "subscript_expression")) return .member_access;

    // Literals
    if (eq(t, "string") or eq(t, "string_fragment")) return .literal;
    if (eq(t, "number")) return .literal;
    if (eq(t, "true") or eq(t, "false") or eq(t, "null") or eq(t, "undefined")) return .literal;
    if (eq(t, "object")) return .literal;
    if (eq(t, "regex")) return .literal;

    // Assignment
    if (eq(t, "variable_declaration") or eq(t, "lexical_declaration")) return .assignment;
    if (eq(t, "variable_declarator")) return .assignment;
    if (eq(t, "assignment_expression")) return .assignment;
    if (eq(t, "pair")) return .assignment;

    // Imports / exports
    if (eq(t, "import_statement")) return .import;
    if (eq(t, "export_statement")) return .import;

    // Control flow
    if (eq(t, "if_statement") or eq(t, "for_statement") or eq(t, "while_statement")) return .control_flow;
    if (eq(t, "for_in_statement") or eq(t, "for_of_statement")) return .control_flow;

    // Operators
    if (eq(t, "binary_expression")) return .binary_op;
    if (eq(t, "unary_expression")) return .unary_op;

    // Structural
    if (eq(t, "return_statement")) return .return_stmt;
    if (eq(t, "statement_block")) return .block;
    if (eq(t, "class_body")) return .block;
    if (eq(t, "formal_parameters")) return .parameter;
    if (eq(t, "arguments")) return .argument;
    if (eq(t, "spread_element")) return .argument;
    if (eq(t, "comment")) return .comment;
    if (eq(t, "expression_statement")) return .expression_stmt;
    if (eq(t, "parenthesized_expression")) return .expression_stmt;
    if (eq(t, "template_string")) return .string_template;
    if (eq(t, "template_substitution")) return .string_template;

    return .unknown;
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Classify a literal node's sub-type from its tree-sitter CST node type.
pub fn classifyLiteral(node_type: []const u8, lang: ts.Language) zir.LiteralKind {
    return switch (lang) {
        .python => classifyLiteralPython(node_type),
        .javascript => classifyLiteralJavaScript(node_type),
    };
}

fn classifyLiteralPython(t: []const u8) zir.LiteralKind {
    if (eq(t, "string")) return .string;
    if (eq(t, "integer")) return .number_int;
    if (eq(t, "float")) return .number_float;
    if (eq(t, "true") or eq(t, "false")) return .boolean;
    if (eq(t, "none")) return .null_value;
    if (eq(t, "list") or eq(t, "dictionary") or eq(t, "tuple")) return .collection;
    return .unknown;
}

fn classifyLiteralJavaScript(t: []const u8) zir.LiteralKind {
    if (eq(t, "string") or eq(t, "string_fragment")) return .string;
    if (eq(t, "number")) return .number_int; // JS has single Number type; default to int
    if (eq(t, "true") or eq(t, "false")) return .boolean;
    if (eq(t, "null") or eq(t, "undefined")) return .null_value;
    if (eq(t, "regex")) return .regex;
    if (eq(t, "object")) return .collection;
    return .unknown;
}

/// Convert a tree-sitter CST into ZIR. Unmapped or error nodes become Kind.unknown.
pub fn buildZir(tree: *zir.ZirTree, node: *const ts.Node, parent_id: ?zir.NodeId, lang: ts.Language) !void {
    return buildZirInner(tree, node, parent_id, lang, false);
}

/// Error-tolerant variant: skips ERROR nodes but still recurses into their children,
/// reparenting them to the error node's parent.
pub fn buildZirErrorTolerant(tree: *zir.ZirTree, node: *const ts.Node, parent_id: ?zir.NodeId, lang: ts.Language) !void {
    return buildZirInner(tree, node, parent_id, lang, true);
}

/// Iterative CST → ZIR conversion using an explicit stack.
/// Handles arbitrarily deep trees (minified JS, deeply nested expressions)
/// without risk of stack overflow.
fn buildZirInner(tree: *zir.ZirTree, root: *const ts.Node, root_parent: ?zir.NodeId, lang: ts.Language, skip_errors: bool) !void {
    const Frame = struct {
        node: ts.Node,
        parent_id: ?zir.NodeId,
        child_idx: u32,
        child_count: u32,
        zir_id: ?zir.NodeId, // null if node was skipped (unnamed or ERROR)
    };

    var stack = std.ArrayList(Frame).init(tree.allocator);
    defer stack.deinit();

    // Push root
    try stack.append(.{
        .node = root.*,
        .parent_id = root_parent,
        .child_idx = 0,
        .child_count = root.childCount(),
        .zir_id = null,
    });

    // Process the root node
    if (root.isNamed()) {
        const should_skip = skip_errors and std.mem.eql(u8, root.nodeType(), "ERROR");
        if (!should_skip) {
            stack.items[0].zir_id = try emitNode(tree, root, root_parent, lang);
        }
    }

    while (stack.items.len > 0) {
        const top = &stack.items[stack.items.len - 1];

        if (top.child_idx >= top.child_count) {
            // All children processed — pop
            _ = stack.pop();
            continue;
        }

        // Get next child
        const child_opt = top.node.child(top.child_idx);
        top.child_idx += 1;

        const child = child_opt orelse continue;
        if (!child.isNamed()) continue;

        // Determine parent ZIR ID for this child
        // If current node was skipped (ERROR in tolerant mode), reparent to grandparent
        const effective_parent = top.zir_id orelse top.parent_id;

        // Check if this child should be skipped (ERROR node in tolerant mode)
        const is_error = skip_errors and std.mem.eql(u8, child.nodeType(), "ERROR");

        var child_zir_id: ?zir.NodeId = null;
        if (!is_error) {
            child_zir_id = try emitNode(tree, &child, effective_parent, lang);
        }

        // Push child frame for processing its children
        if (child.childCount() > 0) {
            try stack.append(.{
                .node = child,
                .parent_id = effective_parent,
                .child_idx = 0,
                .child_count = child.childCount(),
                .zir_id = child_zir_id,
            });
        }
    }
}

/// Emit a single ZIR node from a tree-sitter CST node.
fn emitNode(tree: *zir.ZirTree, node: *const ts.Node, parent_id: ?zir.NodeId, lang: ts.Language) !zir.NodeId {
    var kind = mapKind(node.nodeType(), lang);

    // CommonJS: require('x') is an import, not a call
    if (lang == .javascript and kind == .call) {
        if (node.namedChild(0)) |callee| {
            if (std.mem.eql(u8, callee.nodeType(), "identifier") and
                std.mem.eql(u8, callee.text(), "require"))
            {
                kind = .import;
            }
        }
    }

    // Python: string nodes wrapping f-strings (f"..." / f'...') should be string_template
    if (lang == .python and kind == .literal) {
        const text = node.text();
        if (text.len >= 2 and (text[0] == 'f' or text[0] == 'F') and (text[1] == '"' or text[1] == '\'')) {
            kind = .string_template;
        }
    }

    const sp = node.startPoint();
    const ep = node.endPoint();
    const span = zir.Span{
        .start_byte = node.startByte(),
        .end_byte = node.endByte(),
        .start_row = sp.row,
        .start_col = sp.column,
        .end_row = ep.row,
        .end_col = ep.column,
    };

    const atom: ?zir.AtomId = if (kind == .identifier or kind == .literal)
        try tree.atoms.intern(node.text())
    else
        null;

    var flags: u32 = 0;
    if (node.hasError()) flags |= zir.Node.FLAG_ERROR;
    if (node.isMissing()) flags |= zir.Node.FLAG_MISSING;
    if (node.isNamed()) flags |= zir.Node.FLAG_NAMED;

    // Tier 1: classify literal sub-type from CST node type
    if (kind == .literal) {
        const lit_kind = classifyLiteral(node.nodeType(), lang);
        flags |= @as(u32, @intFromEnum(lit_kind)) << zir.Node.LITERAL_KIND_SHIFT;
    }

    return tree.addNode(kind, span, atom, parent_id, &.{}, flags);
}
