const std = @import("std");
const net = std.net;
const log = std.log;
const Args = @import("zig-args");
const Md5 = std.crypto.hash.Md5;

pub const std_options: std.Options = .{ .log_level = .info };

// Command line arguments struct
const Options = struct {
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

// struct used to send the client the info before sending the file
const Metadata = extern struct { md5sum: [Md5.digest_length]u8, filesize: u64 };

// calculate the md5sum from the reader
fn md5sum(reader: anytype) ![Md5.digest_length]u8 {
    var buff: [2048]u8 = undefined;
    var digest: [Md5.digest_length]u8 = undefined;

    var md5 = Md5.init(.{});
    while (true) {
        const len = try reader.read(&buff);
        if (len == 0) break;

        md5.update(buff[0..len]);
    }
    md5.final(&digest);

    return digest;
}

// get path of the file to download to the client
fn getPath(reader: anytype, dir: []const u8, pathbuf: []u8) ![]const u8 {
    var final: [std.fs.max_path_bytes]u8 = undefined;
    var buff: [std.fs.max_path_bytes]u8 = undefined;
    const path = try reader.readUntilDelimiterOrEof(&buff, '\n') orelse return error.noPath;
    const fullpath = try std.fmt.bufPrint(pathbuf, "{s}/{s}", .{ dir, path });
    const final_size = std.mem.replacementSize(u8, fullpath, "../", "");
    _ = std.mem.replace(u8, fullpath, "../", "", &final);
    return final[0..final_size];
}

fn handle(client: net.Server.Connection, dir: []const u8) !void {
    // get Path from client
    var cbin = std.io.bufferedReader(client.stream.reader());
    var creader = cbin.reader();
    var pathbuff: [std.fs.max_path_bytes]u8 = undefined;
    const fullpath = try getPath(&creader, dir, &pathbuff);
    log.info("Request '{s}'", .{fullpath});

    // get file size
    var file = try std.fs.cwd().openFile(fullpath, .{});
    defer file.close();
    const filestats = try file.stat();
    log.info("Got stat from file", .{});

    // get md5sum from file
    var fbin = std.io.bufferedReader(file.reader());
    var freader = fbin.reader();
    const md5digest = try md5sum(&freader);
    log.info("Got md5hash from file", .{});

    // send Metadata to client
    const infos: Metadata = .{ .md5sum = md5digest, .filesize = filestats.size };
    try client.stream.writer().writeStruct(infos);
    log.info("Sent metadata: {any}", .{infos});

    // send file to client
    _ = try std.posix.sendfile(client.stream.handle, file.handle, 0, 0, &.{}, &.{}, 0);
    log.info("Sent file", .{});
}

fn serve(addr: net.Address, dir: []const u8) !void {
    var server = try addr.listen(.{ .reuse_address = true });
    log.info("Listening on {}", .{server.listen_address});

    while (true) {
        const client = try server.accept();
        defer client.stream.close();
        log.info("New client on {}", .{client.address});
        handle(client, dir) catch |err| {
            log.warn("error: {s}", .{@errorName(err)});
            _ = try client.stream.write(&[1]u8{0} ** Md5.digest_length);
            _ = try client.stream.write(@errorName(err));
        };
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("leak detected");
    const allocator = gpa.allocator();

    // parse arguments
    const args = Args.parseForCurrentProcess(Options, allocator, .print) catch return;
    defer args.deinit();
    if (args.positionals.len != 1) {
        try Args.printHelp(
            Options,
            args.executable_name orelse "zfs",
            std.io.getStdOut().writer(),
        );
        return;
    }

    const ip = args.options.bind;
    const port = try std.fmt.parseUnsigned(u16, args.positionals[0], 10);
    const addr = try net.Address.resolveIp(ip, port);

    try serve(addr, args.options.directory);
}
