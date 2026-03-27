const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- Tree-sitter language grammars (compiled from C) ---
    const ts_python = b.addStaticLibrary(.{
        .name = "tree-sitter-python",
        .target = target,
        .optimize = optimize,
    });
    ts_python.addCSourceFiles(.{
        .files = &.{
            "vendor/tree-sitter-python/src/parser.c",
            "vendor/tree-sitter-python/src/scanner.c",
        },
        .flags = &.{"-std=c11"},
    });
    ts_python.addIncludePath(.{ .cwd_relative = "vendor/tree-sitter-python/src" });
    ts_python.linkLibC();

    const ts_javascript = b.addStaticLibrary(.{
        .name = "tree-sitter-javascript",
        .target = target,
        .optimize = optimize,
    });
    ts_javascript.addCSourceFiles(.{
        .files = &.{
            "vendor/tree-sitter-javascript/src/parser.c",
            "vendor/tree-sitter-javascript/src/scanner.c",
        },
        .flags = &.{"-std=c11"},
    });
    ts_javascript.addIncludePath(.{ .cwd_relative = "vendor/tree-sitter-javascript/src" });
    ts_javascript.linkLibC();

    // --- Hypothesis test executables ---
    const hypotheses = [_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "h1_treesitter_ffi", .path = "hypothesis/h1_treesitter_ffi.zig" },
        .{ .name = "h2_zir_normalization", .path = "hypothesis/h2_zir_normalization.zig" },
        .{ .name = "h3_error_tolerance", .path = "hypothesis/h3_error_tolerance.zig" },
        .{ .name = "h4_pattern_matching", .path = "hypothesis/h4_pattern_matching.zig" },
        .{ .name = "h5_prefilter", .path = "hypothesis/h5_prefilter.zig" },
        .{ .name = "h6_arena_benchmark", .path = "hypothesis/h6_arena_benchmark.zig" },
        .{ .name = "h7_vs_semgrep", .path = "hypothesis/h7_vs_semgrep.zig" },
        .{ .name = "h8_rule_system", .path = "hypothesis/h8_rule_system.zig" },
        .{ .name = "h9_ground_truth", .path = "hypothesis/h9_ground_truth.zig" },
        .{ .name = "h10_indexed_matcher", .path = "hypothesis/h10_indexed_matcher.zig" },
    };

    // Shared module for ZIR types used across hypotheses
    const zir_mod = b.addModule("zir", .{
        .root_source_file = .{ .cwd_relative = "src/zir.zig" },
    });

    const ts_mod = b.addModule("treesitter", .{
        .root_source_file = .{ .cwd_relative = "src/treesitter.zig" },
    });

    const normalizer_mod = b.addModule("normalizer", .{
        .root_source_file = .{ .cwd_relative = "src/normalizer.zig" },
    });
    normalizer_mod.addImport("zir", zir_mod);
    normalizer_mod.addImport("treesitter", ts_mod);

    const rule_mod = b.addModule("rule", .{
        .root_source_file = .{ .cwd_relative = "src/rule.zig" },
    });
    rule_mod.addImport("zir", zir_mod);

    const matcher_mod = b.addModule("matcher", .{
        .root_source_file = .{ .cwd_relative = "src/matcher.zig" },
    });
    matcher_mod.addImport("zir", zir_mod);
    matcher_mod.addImport("rule", rule_mod);

    const sarif_mod = b.addModule("sarif", .{
        .root_source_file = .{ .cwd_relative = "src/sarif.zig" },
    });
    sarif_mod.addImport("rule", rule_mod);
    sarif_mod.addImport("matcher", matcher_mod);

    const fast_matcher_mod = b.addModule("fast_matcher", .{
        .root_source_file = .{ .cwd_relative = "src/fast_matcher.zig" },
    });
    fast_matcher_mod.addImport("zir", zir_mod);
    fast_matcher_mod.addImport("rule", rule_mod);
    fast_matcher_mod.addImport("matcher", matcher_mod);

    const cache_mod = b.addModule("cache", .{
        .root_source_file = .{ .cwd_relative = "src/cache.zig" },
    });
    cache_mod.addImport("rule", rule_mod);
    cache_mod.addImport("matcher", matcher_mod);
    cache_mod.addImport("zir", zir_mod);

    // --- Main CLI executable: zent ---
    const zent = b.addExecutable(.{
        .name = "zent",
        .root_source_file = .{ .cwd_relative = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    zent.linkSystemLibrary("tree-sitter");
    zent.linkLibrary(ts_python);
    zent.linkLibrary(ts_javascript);
    zent.linkLibC();
    zent.addIncludePath(.{ .cwd_relative = "vendor/tree-sitter-python/src" });
    zent.addIncludePath(.{ .cwd_relative = "vendor/tree-sitter-javascript/src" });
    zent.root_module.addImport("zir", zir_mod);
    zent.root_module.addImport("treesitter", ts_mod);
    zent.root_module.addImport("normalizer", normalizer_mod);
    zent.root_module.addImport("rule", rule_mod);
    zent.root_module.addImport("matcher", matcher_mod);
    zent.root_module.addImport("sarif", sarif_mod);
    zent.root_module.addImport("fast_matcher", fast_matcher_mod);
    zent.root_module.addImport("cache", cache_mod);
    b.installArtifact(zent);

    const run_zent = b.addRunArtifact(zent);
    run_zent.step.dependOn(b.getInstallStep());
    if (b.args) |run_args| {
        run_zent.addArgs(run_args);
    }
    const run_step = b.step("run", "Run the zent CLI");
    run_step.dependOn(&run_zent.step);

    // --- Fuzz harness ---
    const fuzz_exe = b.addExecutable(.{
        .name = "fuzz",
        .root_source_file = .{ .cwd_relative = "fuzz/fuzz.zig" },
        .target = target,
        .optimize = .ReleaseSafe, // Safety checks ON + compiler optimizations
    });
    fuzz_exe.linkSystemLibrary("tree-sitter");
    fuzz_exe.linkLibrary(ts_python);
    fuzz_exe.linkLibrary(ts_javascript);
    fuzz_exe.linkLibC();
    fuzz_exe.addIncludePath(.{ .cwd_relative = "vendor/tree-sitter-python/src" });
    fuzz_exe.addIncludePath(.{ .cwd_relative = "vendor/tree-sitter-javascript/src" });
    fuzz_exe.root_module.addImport("zir", zir_mod);
    fuzz_exe.root_module.addImport("treesitter", ts_mod);
    fuzz_exe.root_module.addImport("normalizer", normalizer_mod);
    fuzz_exe.root_module.addImport("rule", rule_mod);
    fuzz_exe.root_module.addImport("matcher", matcher_mod);
    fuzz_exe.root_module.addImport("fast_matcher", fast_matcher_mod);
    fuzz_exe.root_module.addImport("cache", cache_mod);
    b.installArtifact(fuzz_exe);

    const run_fuzz = b.addRunArtifact(fuzz_exe);
    run_fuzz.step.dependOn(b.getInstallStep());
    if (b.args) |run_args| run_fuzz.addArgs(run_args);
    const fuzz_step = b.step("fuzz", "Run the fuzz harness");
    fuzz_step.dependOn(&run_fuzz.step);

    // --- Hypothesis test executables ---
    // A step to build and run ALL hypotheses
    const run_all_step = b.step("hypothesis", "Run all hypothesis tests");

    for (hypotheses) |h| {
        const exe = b.addExecutable(.{
            .name = h.name,
            .root_source_file = .{ .cwd_relative = h.path },
            .target = target,
            .optimize = optimize,
        });

        // Link system tree-sitter + compiled grammars
        exe.linkSystemLibrary("tree-sitter");
        exe.linkLibrary(ts_python);
        exe.linkLibrary(ts_javascript);
        exe.linkLibC();

        // Add include paths for tree-sitter headers
        exe.addIncludePath(.{ .cwd_relative = "vendor/tree-sitter-python/src" });
        exe.addIncludePath(.{ .cwd_relative = "vendor/tree-sitter-javascript/src" });

        // Add shared modules
        exe.root_module.addImport("zir", zir_mod);
        exe.root_module.addImport("treesitter", ts_mod);
        exe.root_module.addImport("normalizer", normalizer_mod);
        exe.root_module.addImport("rule", rule_mod);
        exe.root_module.addImport("matcher", matcher_mod);
        exe.root_module.addImport("sarif", sarif_mod);
        exe.root_module.addImport("fast_matcher", fast_matcher_mod);
        exe.root_module.addImport("cache", cache_mod);

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        // Individual run step: zig build run-h1_treesitter_ffi
        const h_run_step = b.step(b.fmt("run-{s}", .{h.name}), b.fmt("Run {s}", .{h.name}));
        h_run_step.dependOn(&run_cmd.step);

        run_all_step.dependOn(&run_cmd.step);
    }
}
