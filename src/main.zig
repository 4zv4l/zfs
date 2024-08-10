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

// send error to client as 0ed md5hash + err.len + err
fn sendError(writer: anytype, err: anyerror) !void {
    const strerror = @errorName(err);
    log.warn("{s}", .{strerror});
    _ = try writer.writeStruct(Metadata{
        .md5sum = .{0} ** Md5.digest_length,
        .filesize = strerror.len,
    });
    _ = try writer.write(strerror);
}

// modify the given path to remove the '../'
fn sanitizePath(path: []u8) []const u8 {
    var pathbuff: [std.fs.max_path_bytes]u8 = undefined;
    const max_len = @min(pathbuff.len, path.len);
    @memcpy(pathbuff[0..max_len], path[0..max_len]);

    const final_size = std.mem.replacementSize(u8, path[0..max_len], "../", "");
    _ = std.mem.replace(u8, path, "../", "", pathbuff[0..max_len]);
    @memcpy(path[0..final_size], pathbuff[0..final_size]);

    return path[0..final_size];
}

// TODO: setup Comptime String HashMap if more commands, for now only ls (only entry name)
fn sendCmd(client: net.Server.Connection, root: []const u8, cmd: []u8) !void {
    const allocator = std.heap.page_allocator;
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    if (cmd.len >= 2 and std.mem.eql(u8, cmd[0..2], "ls")) {
        const sane_path = if (cmd.len > 3) sanitizePath(cmd[3..]) else "";
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

        // get md5sum and send Metadata to the client
        var checksum: [Md5.digest_length]u8 = undefined;
        Md5.hash(output.items, &checksum, .{});
        const metadata = Metadata{ .md5sum = checksum, .filesize = output.items.len };
        try client.stream.writer().writeStruct(metadata);
        log.info(
            "Sent metadata: {{ hash: {s}, size: {d} }}",
            .{ std.fmt.fmtSliceHexLower(&metadata.md5sum), metadata.filesize },
        );

        // send command output
        try client.stream.writeAll(output.items);
    } else {
        try sendError(client.stream.writer(), error.CommandNotFound);
    }
}

// sanitize filename given by client and send the md5sum + size, then send the file content
fn sendFile(client: net.Server.Connection, root: []const u8, path: []u8) !void {
    // clean path given by client
    const sane_path = sanitizePath(path);
    log.info("Request '{s}/{s}'", .{ root, sane_path });

    // get file size
    var dir = try std.fs.cwd().openDir(root, .{});
    defer dir.close();
    var file = try dir.openFile(sane_path, .{});
    defer file.close();
    const filestats = try file.stat();
    log.info("Got stat from file", .{});

    // get md5sum from file
    var fbin = std.io.bufferedReader(file.reader());
    var freader = fbin.reader();
    const md5digest = try md5sum(&freader);
    log.info("Got md5hash from file", .{});

    // send Metadata to client
    const metadata: Metadata = .{ .md5sum = md5digest, .filesize = filestats.size };
    try client.stream.writer().writeStruct(metadata);
    log.info(
        "Sent metadata: {{ hash: {s}, size: {d} }}",
        .{ std.fmt.fmtSliceHexLower(&metadata.md5sum), metadata.filesize },
    );

    // send file to client
    _ = try std.posix.sendfile(client.stream.handle, file.handle, 0, 0, &.{}, &.{}, 0);
    log.info("Sent file", .{});
}

// get the client's request and send the command output/file
fn handle(client: net.Server.Connection, root: []const u8) !void {
    var cbin = std.io.bufferedReader(client.stream.reader());
    var creader = cbin.reader();
    var buff: [2048]u8 = undefined;

    // get client's request, if starts by a '$' then its a command
    const request = try creader.readUntilDelimiterOrEof(&buff, '\n') orelse return error.clientEOF;
    if (std.mem.startsWith(u8, request, "$")) {
        try sendCmd(client, root, request[1..]);
    } else {
        try sendFile(client, root, request);
    }
}

// client loop letting client download multiple files per session
fn clientLoop(client: net.Server.Connection, dir: []const u8, counter: *std.atomic.Value(u8)) void {
    defer client.stream.close();
    defer _ = counter.fetchSub(1, .seq_cst);

    while (true) {
        handle(client, dir) catch |err| {
            if (err == error.clientEOF) {
                log.info("Client {} left", .{client.address});
                break;
            }
            sendError(client.stream.writer(), err) catch break;
        };
    }
}

// accept client in a loop creating a thread per client
fn serve(addr: net.Address, dir: []const u8) !void {
    var server = try addr.listen(.{ .reuse_address = true });
    log.info("Listening on {} and serving {s}/", .{ server.listen_address, dir });

    // setup thread pool
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = std.heap.page_allocator });
    defer pool.deinit();

    // accept client in a loop, if all threads are occupied
    // prevent new client from waiting (close their connection, sending ClientQueueIsFull)
    var client_counter = std.atomic.Value(u8).init(0);
    while (true) {
        const client = try server.accept();
        if (client_counter.load(.seq_cst) == pool.threads.len) {
            defer client.stream.close();
            sendError(client.stream.writer(), error.ClientQueueIsFull) catch continue;
            continue;
        }
        try pool.spawn(clientLoop, .{ client, dir, &client_counter });
        log.info("New client on {} [{d}/{d}]", .{
            client.address,
            client_counter.fetchAdd(1, .seq_cst) + 1,
            pool.threads.len,
        });
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
