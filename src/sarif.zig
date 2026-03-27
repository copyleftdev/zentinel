/// SARIF v2.1.0 output formatter.
/// Generates Static Analysis Results Interchange Format JSON from scan findings.
const std = @import("std");
const rule = @import("rule");
const matcher = @import("matcher");

/// A single file's findings, grouped for SARIF output.
pub const FileFindings = struct {
    path: []const u8,
    findings: []const matcher.Finding,
};

/// Write a complete SARIF v2.1.0 JSON log to the writer.
pub fn writeSarif(
    writer: anytype,
    file_results: []const FileFindings,
    compiled_rules: []const rule.CompiledRule,
) !void {
    try writer.writeAll(
        \\{
        \\  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        \\  "version": "2.1.0",
        \\  "runs": [
        \\    {
        \\      "tool": {
        \\        "driver": {
        \\          "name": "zentinel",
        \\          "semanticVersion": "0.1.0",
        \\          "informationUri": "https://github.com/zentinel/zentinel",
        \\          "rules": [
    );

    // Write rule definitions
    for (compiled_rules, 0..) |cr, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("\n            {\n");
        try writer.writeAll("              \"id\": \"");
        try writeJsonEscaped(writer, cr.rule.id);
        try writer.writeAll("\",\n              \"shortDescription\": { \"text\": \"");
        try writeJsonEscaped(writer, cr.rule.message);
        try writer.writeAll("\" },\n              \"defaultConfiguration\": { \"level\": \"");
        try writer.writeAll(sarifLevel(cr.rule.severity));
        try writer.writeAll("\" }\n            }");
    }

    try writer.writeAll(
        \\
        \\          ]
        \\        }
        \\      },
        \\      "results": [
    );

    // Write results
    var first_result = true;
    for (file_results) |fr| {
        for (fr.findings) |f| {
            if (!first_result) try writer.writeAll(",");
            first_result = false;

            try writer.writeAll("\n        {\n");

            // ruleId
            try writer.writeAll("          \"ruleId\": \"");
            try writeJsonEscaped(writer, f.rule_id);
            try writer.writeAll("\",\n");

            // level
            try writer.writeAll("          \"level\": \"");
            try writer.writeAll(sarifLevel(f.severity));
            try writer.writeAll("\",\n");

            // message
            try writer.writeAll("          \"message\": { \"text\": \"");
            try writeJsonEscaped(writer, f.message);
            try writer.writeAll("\" },\n");

            // locations
            try writer.writeAll("          \"locations\": [\n");
            try writer.writeAll("            {\n");
            try writer.writeAll("              \"physicalLocation\": {\n");
            try writer.writeAll("                \"artifactLocation\": { \"uri\": \"");
            try writeJsonEscaped(writer, fr.path);
            try writer.writeAll("\" },\n");
            try writer.print(
                "                \"region\": {{ \"startLine\": {d}, \"startColumn\": {d}, \"endLine\": {d}, \"endColumn\": {d} }}\n",
                .{
                    f.span.start_row + 1,
                    f.span.start_col + 1,
                    f.span.end_row + 1,
                    f.span.end_col + 1,
                },
            );
            try writer.writeAll("              }\n");
            try writer.writeAll("            }\n");
            try writer.writeAll("          ]\n");
            try writer.writeAll("        }");
        }
    }

    try writer.writeAll(
        \\
        \\      ]
        \\    }
        \\  ]
        \\}
        \\
    );
}

fn sarifLevel(severity: rule.Severity) []const u8 {
    return switch (severity) {
        .ERROR => "error",
        .WARNING => "warning",
        .INFO => "note",
    };
}

fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(c),
        }
    }
}
