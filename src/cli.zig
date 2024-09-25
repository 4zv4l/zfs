const std = @import("std");
const cli = @import("args");

// Command line arguments struct
pub const Options = struct {
    help: bool = false,
    directory: []const u8 = ".",
    bind: []const u8 = "0.0.0.0",

    pub const shorthands = .{
        .h = "help",
        .d = "directory",
        .b = "bind",
    };

    pub const meta = .{
        .usage_summary = "[-h] [-d directory] [-b address] [port]",
        .option_docs = .{
            .help = "Show this help",
            .directory = "Serve this directory (default: current directory)",
            .bind = "Bind to this address (default: all interfaces)",
        },
    };
};

pub fn parse(allocator: std.mem.Allocator) !cli.ParseArgsResult(Options, null) {
    const args = try cli.parseForCurrentProcess(Options, allocator, .print);
    return args;
}

pub fn usage(exe_name: ?[]const u8) !void {
    try cli.printHelp(Options, exe_name orelse "zfs", std.io.getStdOut().writer());
}
