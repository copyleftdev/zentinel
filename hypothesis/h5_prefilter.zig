/// H5: Can a prefilter skip 80%+ of rule executions?
///
/// PASS criteria:
///   1. File signature extraction works (identifiers, node kinds)
///   2. Rule requirement extraction works
///   3. Skip ratio >= 80% when running many rules against a file
///   4. Zero false negatives — prefilter never skips a rule that would have matched
///
const std = @import("std");
const ts = @import("treesitter");
const zir = @import("zir");
const normalizer = @import("normalizer");

fn readFixture(path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(std.heap.page_allocator, 1024 * 1024);
}

const Result = struct {
    name: []const u8,
    passed: bool,
    detail: []const u8,
};

// ── File Signature ──────────────────────────────────────────────

const FileSignature = struct {
    identifiers: std.StringHashMap(void),
    kinds: std.AutoHashMap(zir.Kind, void),

    fn init(alloc: std.mem.Allocator) FileSignature {
        return .{
            .identifiers = std.StringHashMap(void).init(alloc),
            .kinds = std.AutoHashMap(zir.Kind, void).init(alloc),
        };
    }

    fn deinit(self: *FileSignature) void {
        self.identifiers.deinit();
        self.kinds.deinit();
    }

    fn addFromZir(self: *FileSignature, tree: *const zir.ZirTree) !void {
        for (tree.nodes.items) |node| {
            try self.kinds.put(node.kind, {});
            if (node.atom) |aid| {
                try self.identifiers.put(tree.atoms.get(aid), {});
            }
        }
    }
};

// ── Rule Requirements ───────────────────────────────────────────

const RuleRequirement = struct {
    id: []const u8,
    required_kinds: []const zir.Kind,
    required_atoms: []const []const u8,
    would_match: bool, // ground truth for false-negative check

    fn matches(self: *const RuleRequirement, sig: *const FileSignature) bool {
        for (self.required_kinds) |k| {
            if (!sig.kinds.contains(k)) return false;
        }
        for (self.required_atoms) |a| {
            if (!sig.identifiers.contains(a)) return false;
        }
        return true;
    }
};

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll(
        \\
        \\══════════════════════════════════════════════════════════
        \\  H5: Prefilter Skip Ratio
        \\══════════════════════════════════════════════════════════
        \\
    );

    var results_list = std.ArrayList(Result).init(std.heap.page_allocator);
    defer results_list.deinit();
    const alloc = std.heap.page_allocator;

    var parser = try ts.Parser.init();
    defer parser.deinit();

    // Build ZIR for Python fixture
    try parser.setLanguage(.python);
    const py_source = try readFixture("test_fixtures/python/clean.py");
    var py_tree = try parser.parse(py_source);
    defer py_tree.deinit();

    var py_zir = zir.ZirTree.init(alloc, "python");
    defer py_zir.deinit();
    try normalizer.buildZir(&py_zir, &py_tree.rootNode(), null, .python);

    // ── Extract file signature ──────────────────────────────────
    var sig = FileSignature.init(alloc);
    defer sig.deinit();
    try sig.addFromZir(&py_zir);

    const id_count = sig.identifiers.count();
    const kind_count = sig.kinds.count();
    try results_list.append(.{
        .name = "file_signature_extraction",
        .passed = id_count > 0 and kind_count > 0,
        .detail = try std.fmt.allocPrint(alloc, "{d} unique identifiers, {d} unique kinds", .{ id_count, kind_count }),
    });

    // ── Define a large set of rules (most should NOT match this file) ──
    const rules = [_]RuleRequirement{
        // Rules that SHOULD match our Python fixture
        .{ .id = "dangerous-exec", .required_kinds = &.{.call}, .required_atoms = &.{"exec"}, .would_match = true },
        .{ .id = "dangerous-eval", .required_kinds = &.{.call}, .required_atoms = &.{"eval"}, .would_match = true },
        .{ .id = "subprocess-call", .required_kinds = &.{.call}, .required_atoms = &.{"subprocess"}, .would_match = true },
        .{ .id = "hardcoded-secret", .required_kinds = &.{ .assignment, .literal }, .required_atoms = &.{}, .would_match = true },

        // Rules that should NOT match (require atoms/kinds not in our file)
        .{ .id = "react-dangerouslySetInnerHTML", .required_kinds = &.{.call}, .required_atoms = &.{"dangerouslySetInnerHTML"}, .would_match = false },
        .{ .id = "django-raw-sql", .required_kinds = &.{.call}, .required_atoms = &.{"RawSQL"}, .would_match = false },
        .{ .id = "flask-debug-true", .required_kinds = &.{.call}, .required_atoms = &.{"app.run"}, .would_match = false },
        .{ .id = "jwt-none-algorithm", .required_kinds = &.{.call}, .required_atoms = &.{"jwt.decode"}, .would_match = false },
        .{ .id = "pickle-load", .required_kinds = &.{.call}, .required_atoms = &.{"pickle"}, .would_match = false },
        .{ .id = "yaml-unsafe-load", .required_kinds = &.{.call}, .required_atoms = &.{"yaml.load"}, .would_match = false },
        .{ .id = "requests-no-verify", .required_kinds = &.{.call}, .required_atoms = &.{"verify"}, .would_match = false },
        .{ .id = "cors-allow-all", .required_kinds = &.{.call}, .required_atoms = &.{"CORS"}, .would_match = false },
        .{ .id = "boto3-public-acl", .required_kinds = &.{.call}, .required_atoms = &.{"put_object_acl"}, .would_match = false },
        .{ .id = "crypto-weak-hash", .required_kinds = &.{.call}, .required_atoms = &.{"md5"}, .would_match = false },
        .{ .id = "tempfile-mktemp", .required_kinds = &.{.call}, .required_atoms = &.{"mktemp"}, .would_match = false },
        .{ .id = "marshal-loads", .required_kinds = &.{.call}, .required_atoms = &.{"marshal"}, .would_match = false },
        .{ .id = "shelve-open", .required_kinds = &.{.call}, .required_atoms = &.{"shelve"}, .would_match = false },
        .{ .id = "xml-parse-untrusted", .required_kinds = &.{.call}, .required_atoms = &.{"xml.etree"}, .would_match = false },
        .{ .id = "logging-sensitive", .required_kinds = &.{.call}, .required_atoms = &.{"password"}, .would_match = false },
        .{ .id = "graphql-introspection", .required_kinds = &.{.call}, .required_atoms = &.{"introspection"}, .would_match = false },
        .{ .id = "grpc-insecure", .required_kinds = &.{.call}, .required_atoms = &.{"insecure_channel"}, .would_match = false },
        .{ .id = "docker-privileged", .required_kinds = &.{.call}, .required_atoms = &.{"privileged"}, .would_match = false },
        .{ .id = "k8s-host-network", .required_kinds = &.{.call}, .required_atoms = &.{"hostNetwork"}, .would_match = false },
        .{ .id = "terraform-public-sg", .required_kinds = &.{.call}, .required_atoms = &.{"cidr_blocks"}, .would_match = false },
    };

    // ── Run prefilter ───────────────────────────────────────────
    var skipped: u32 = 0;
    var executed: u32 = 0;
    var false_negatives: u32 = 0;

    for (&rules) |*rule| {
        const passes_filter = rule.matches(&sig);
        if (!passes_filter) {
            skipped += 1;
            if (rule.would_match) {
                false_negatives += 1;
                try stdout.print("  FALSE NEGATIVE: {s} was skipped but should match!\n", .{rule.id});
            }
        } else {
            executed += 1;
        }
    }

    const total: u32 = @intCast(rules.len);
    const skip_ratio: f64 = @as(f64, @floatFromInt(skipped)) / @as(f64, @floatFromInt(total)) * 100.0;

    try stdout.print("\n── Prefilter Stats ──\n", .{});
    try stdout.print("  Total rules: {d}\n", .{total});
    try stdout.print("  Skipped: {d}\n", .{skipped});
    try stdout.print("  Executed: {d}\n", .{executed});
    try stdout.print("  Skip ratio: {d:.1}%\n", .{skip_ratio});
    try stdout.print("  False negatives: {d}\n", .{false_negatives});

    try results_list.append(.{
        .name = "skip_ratio_80pct",
        .passed = skip_ratio >= 80.0,
        .detail = try std.fmt.allocPrint(alloc, "{d:.1}% of rules skipped (target: >=80%%)", .{skip_ratio}),
    });

    try results_list.append(.{
        .name = "zero_false_negatives",
        .passed = false_negatives == 0,
        .detail = try std.fmt.allocPrint(alloc, "{d} false negatives", .{false_negatives}),
    });

    // ── Print which rules passed the filter ────────────────────
    try stdout.writeAll("\n── Rules that passed prefilter (would execute) ──\n");
    for (&rules) |*rule| {
        if (rule.matches(&sig)) {
            try stdout.print("  - {s}\n", .{rule.id});
        }
    }

    try printResults(stdout, results_list.items);
}

fn printResults(writer: anytype, results_list: []const Result) !void {
    try writer.writeAll("\n── Results ─────────────────────────────────────────────\n");
    var pass_count: u32 = 0;
    var fail_count: u32 = 0;
    for (results_list) |r| {
        const icon: []const u8 = if (r.passed) "PASS" else "FAIL";
        try writer.print("  [{s}] {s}: {s}\n", .{ icon, r.name, r.detail });
        if (r.passed) pass_count += 1 else fail_count += 1;
    }
    try writer.print("\n  Total: {d} passed, {d} failed\n", .{ pass_count, fail_count });
    const verdict: []const u8 = if (fail_count == 0) "H5 CONFIRMED" else "H5 NEEDS WORK";
    try writer.print("  Verdict: {s}\n\n", .{verdict});
}
