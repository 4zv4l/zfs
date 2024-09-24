const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "zfs",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // add dependencies
    const colored_logger = b.dependency("colored_logger", .{ .project_name = exe.name });
    exe.root_module.addImport("colored_logger", colored_logger.module("colored_logger"));
    const argParser = b.dependency("args", .{});
    exe.root_module.addImport("args", argParser.module("args"));

    // compile exe
    b.installArtifact(exe);
}
