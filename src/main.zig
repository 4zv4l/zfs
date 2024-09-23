const std = @import("std");
const Chameleon = @import("chameleon");
const time = @import("time.zig");
const net = std.net;
const log = std.log;
const utils = @import("utils.zig");
const cli = @import("args");
const Commands = @import("cmd.zig").Commands;
const Options = @import("args.zig").Options;
const Metadata = @import("proto.zig").Metadata;
const Md5 = std.crypto.hash.Md5;

pub const std_options: std.Options = .{ .log_level = .info, .logFn = myLogFn };

// custom logging function
pub fn myLogFn(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    comptime var c = Chameleon.initComptime();
    const level_txt = comptime switch (message_level) {
        .warn => c.yellow().fmt("WARN "),
        .info => c.blue().fmt("INFO "),
        .debug => c.white().fmt("DEBUG"),
        .err => c.red().fmt("ERR  "),
    };
    const prefix2 = if (scope == .default) " " else "(" ++ @tagName(scope) ++ ") ";
    const stderr = std.io.getStdErr().writer();
    var bw = std.io.bufferedWriter(stderr);
    const writer = bw.writer();

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    nosuspend {
        // 2024-09-23T08:27:16Z
        time.DateTime.now().format("YYY-MM-DDTHH:mm:ssZ", .{}, writer) catch return;
        writer.print(" " ++ level_txt ++ prefix2 ++ "[" ++ "zfs" ++ "] " ++ format ++ "\n", args) catch return;
        bw.flush() catch return;
    }
}

// contain the current Configuration
pub const Config = struct {
    root: []const u8 = ".",
    local_addr: net.Address = net.Address.parseIp4("0.0.0.0", 8080) catch unreachable,
};

// execute command and send output to client
// return true if the client wants to disconnect properly
fn sendCmd(config: Config, client: net.Server.Connection, req: []u8) !bool {
    // setup allocator and output buffer
    const allocator = std.heap.page_allocator;
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    // check cmd and args and execute if found in the list of cmds
    // $quit close the connection with the client
    const command = req[0 .. std.mem.indexOf(u8, req, " ") orelse req.len];
    log.info("Request cmd '{s}'", .{req});
    if (std.mem.eql(u8, command, "quit")) return true;

    if (Commands.get(command)) |cmd| {
        const arg = if (req.len > command.len + 1) req[command.len + 1 ..] else null;
        try cmd(config.root, arg, &output);
    } else return error.CommandNotFound;

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
    return false;
}

// sanitize filename given by client and send the md5sum + size, then send the file content
fn sendFile(config: Config, client: net.Server.Connection, path: []u8) !void {
    // clean path given by client
    const sane_path = utils.sanitizePath(path);
    log.info("Request '{s}/{s}'", .{ config.root, sane_path });

    // get and send Metadata to client
    var dir = try std.fs.cwd().openDir(config.root, .{});
    defer dir.close();
    var file = try dir.openFile(sane_path, .{});
    defer file.close();
    const metadata = try Metadata.getMetadataFile(file);
    try client.stream.writer().writeStruct(metadata);

    log.info(
        "Sent metadata: {{ hash: {s}, size: {d} }}",
        .{ std.fmt.fmtSliceHexLower(&metadata.md5sum), metadata.filesize },
    );

    // send file to client
    _ = try std.posix.sendfile(
        client.stream.handle,
        file.handle,
        0,
        0,
        &.{},
        &.{},
        0,
    );
    log.info("Sent file", .{});
}

// get the client's request and send the command output/file
fn handleClient(config: Config, client: net.Server.Connection) !void {
    var cbin = std.io.bufferedReader(client.stream.reader());
    var creader = cbin.reader();
    var buff: [2048]u8 = undefined;

    // get client's request, if starts by a '$' then its a command
    const request = try creader.readUntilDelimiterOrEof(&buff, '\n') orelse return error.clientEOF;
    if (std.mem.startsWith(u8, request, "$")) {
        if (try sendCmd(config, client, request[1..])) return error.clientEOF;
    } else {
        try sendFile(config, client, request);
    }
}

// client loop letting client download multiple files per session
fn clientLoop(config: Config, client: net.Server.Connection, counter: *std.atomic.Value(u8)) void {
    defer client.stream.close();
    defer _ = counter.fetchSub(1, .seq_cst);

    while (true) {
        handleClient(config, client) catch |err| {
            if (err == error.clientEOF) {
                log.info("Client {} left", .{client.address});
                break;
            }
            utils.sendError(client.stream.writer(), err) catch break;
        };
    }
}

// accept client in a loop creating a thread per client
fn serve(config: Config) !void {
    var server = try config.local_addr.listen(.{ .reuse_address = true });
    log.info("Listening on {} and serving {s}/", .{ config.local_addr, config.root });

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
            utils.sendError(client.stream.writer(), error.ClientQueueIsFull) catch continue;
            continue;
        }
        try pool.spawn(clientLoop, .{ config, client, &client_counter });
        log.info("New client on {} [{d}/{d}]", .{
            client.address,
            client_counter.fetchAdd(1, .seq_cst) + 1,
            pool.threads.len,
        });
    }
}

pub fn main() !void {
    // setup allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("leak detected");
    const allocator = gpa.allocator();

    // parse arguments
    const args = cli.parseForCurrentProcess(Options, allocator, .print) catch return;
    defer args.deinit();
    if (args.positionals.len != 1) {
        try cli.printHelp(Options, args.executable_name orelse "zfs", std.io.getStdOut().writer());
        return;
    }

    // parse address
    const ip = args.options.bind;
    const port = try std.fmt.parseUnsigned(u16, args.positionals[0], 10);
    const addr = try net.Address.parseIp(ip, port);

    // remove trailing / from directory path
    const dir = std.mem.trimRight(u8, args.options.directory, "/");

    const config: Config = .{ .root = dir, .local_addr = addr };
    try serve(config);
}
