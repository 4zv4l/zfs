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
fn getPath(reader: anytype, pathbuf: []u8) ![]const u8 {
    var buff: [std.fs.max_path_bytes]u8 = undefined;
    const path = try reader.readUntilDelimiterOrEof(&buff, '\n') orelse return error.clientEOF;
    const final_size = std.mem.replacementSize(u8, path, "../", "");
    _ = std.mem.replace(u8, path, "../", "", pathbuf);
    return pathbuf[0..final_size];
}

fn handle(client: net.Server.Connection, path: []const u8) !void {
    // get Path from client
    var cbin = std.io.bufferedReader(client.stream.reader());
    var creader = cbin.reader();
    var pathbuff: [std.fs.max_path_bytes]u8 = undefined;
    const fullpath = try getPath(&creader, &pathbuff);
    log.info("Request '{s}/{s}'", .{ path, fullpath });

    // get file size
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    var file = try dir.openFile(fullpath, .{});
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
    log.info(
        "Sent metadata: {{ hash: {s}, size: {d} }}",
        .{ std.fmt.fmtSliceHexLower(&infos.md5sum), infos.filesize },
    );

    // send file to client
    _ = try std.posix.sendfile(client.stream.handle, file.handle, 0, 0, &.{}, &.{}, 0);
    log.info("Sent file", .{});
}

fn clientLoop(client: net.Server.Connection, dir: []const u8) void {
    defer client.stream.close();

    var ok = true;
    while (ok) {
        handle(client, dir) catch |err| {
            const strerror = @errorName(err);
            log.warn("{s}", .{strerror});
            if (err == error.clientEOF) ok = false;
            _ = client.stream.writer().writeStruct(Metadata{
                .md5sum = .{0} ** Md5.digest_length,
                .filesize = strerror.len,
            }) catch {};
            _ = client.stream.write(strerror) catch {};
        };
    }
}

fn serve(addr: net.Address, dir: []const u8) !void {
    var server = try addr.listen(.{ .reuse_address = true });
    log.info("Listening on {} and serving {s}/", .{ server.listen_address, dir });

    while (true) {
        const client = try server.accept();
        log.info("New client on {}", .{client.address});
        clientLoop(client, dir);
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

    // parse address
    const ip = args.options.bind;
    const port = try std.fmt.parseUnsigned(u16, args.positionals[0], 10);
    const addr = try net.Address.parseIp(ip, port);

    // remove trailing / from directory path
    const dir = std.mem.trimRight(u8, args.options.directory, "/");

    try serve(addr, dir);
}
