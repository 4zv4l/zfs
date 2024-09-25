const std = @import("std");
const net = std.net;
const utils = @import("utils.zig");

const fntype = *const fn (root: []const u8, args: ?[]u8, output: *std.ArrayList(u8)) anyerror!void;
pub const Commands = std.StaticStringMap(fntype).initComptime(.{
    .{ "ls", ls },
});

fn ls(root: []const u8, path: ?[]u8, output: *std.ArrayList(u8)) !void {
    const sane_path = if (path) |p| utils.sanitizePath(p) else ".";
    var buffpath: [std.fs.max_path_bytes]u8 = undefined;
    const fullpath = try std.fmt.bufPrint(&buffpath, "{s}/{s}", .{ root, sane_path });
    var dir = try std.fs.cwd().openDir(fullpath, .{});
    defer dir.close();

    // add to the output buffer all the entry
    // append / if the entry is a directory
    var it = dir.iterate();
    while (try it.next()) |entry| {
        try output.writer().print("{s}{s}\n", .{
            entry.name,
            if (entry.kind == .directory) "/" else "",
        });
    }
}
