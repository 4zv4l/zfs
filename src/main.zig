const std = @import("std");
const net = std.net;
const log = std.log;
const mem = std.mem;
const print = std.debug.print;
const utils = @import("utils.zig");
const Commands = @import("commands.zig").Commands;
const Cli = @import("cli.zig");
const Metadata = @import("proto.zig").Metadata;
const colored_logger = @import("colored_logger");

pub const std_options: std.Options = .{ .log_level = .info, .logFn = colored_logger.myLogFn };

// contain the current Configuration
pub const Ctx = struct {
    root: []const u8 = ".",
    local_addr: net.Address = net.Address.parseIp4("0.0.0.0", 8080) catch unreachable,
    allocator: mem.Allocator,
};

// execute command and send output to client
// return true if the client wants to disconnect properly
fn sendCmd(ctx: Ctx, client: net.Server.Connection, req: []u8) !bool {
    // setup allocator and output buffer
    var output = std.ArrayList(u8).init(ctx.allocator);
    defer output.deinit();

    // check cmd and args and execute if found in the list of cmds
    // $quit close the connection with the client
    const command = req[0 .. mem.indexOf(u8, req, " ") orelse req.len];
    log.info("Request cmd '{s}'", .{req});
    if (mem.eql(u8, command, "quit")) return true;

    if (Commands.get(command)) |cmd| {
        const arg = if (req.len > command.len + 1) req[command.len + 1 ..] else null;
        try cmd(ctx.root, arg, &output);
    } else return error.CommandNotFound;

    // get md5sum and send Metadata to the client
    try Metadata.sendCmdMetadata(client.stream.writer(), output.items);

    // send command output
    try client.stream.writeAll(output.items);
    return false;
}

// sanitize filename given by client and send the md5sum + size, then send the file content
fn sendFile(ctx: Ctx, client: net.Server.Connection, path: []u8) !void {
    // clean path given by client
    const sane_path = utils.sanitizePath(path);
    log.info("Request '{s}/{s}'", .{ ctx.root, sane_path });

    // get and send Metadata to client
    var dir = try std.fs.cwd().openDir(ctx.root, .{});
    defer dir.close();
    var file = try dir.openFile(sane_path, .{});
    defer file.close();
    try Metadata.sendFileMetadata(client.stream.writer(), file);

    // send file to client
    _ = try std.posix.sendfile(client.stream.handle, file.handle, 0, 0, &.{}, &.{}, 0);
    log.info("Sent file", .{});
}

// get the client's request and send the command output/file
fn handleClient(ctx: Ctx, client: net.Server.Connection) !void {
    var cbin = std.io.bufferedReader(client.stream.reader());
    var creader = cbin.reader();
    var buff: [2048]u8 = undefined;

    // get client's request, if starts by a '$' then its a command
    const request = try creader.readUntilDelimiterOrEof(&buff, '\n') orelse return error.clientEOF;
    if (mem.startsWith(u8, request, "$")) {
        if (try sendCmd(ctx, client, request[1..])) return error.clientEOF;
    } else {
        try sendFile(ctx, client, request);
    }
}

// client loop letting client download multiple files per session
fn clientLoop(ctx: Ctx, client: net.Server.Connection, counter: *std.atomic.Value(u8)) void {
    defer client.stream.close();
    defer _ = counter.fetchSub(1, .seq_cst);

    while (true) {
        handleClient(ctx, client) catch |err| {
            if (err == error.clientEOF) {
                log.info("Client {} left", .{client.address});
                break;
            }
            Metadata.sendError(client.stream.writer(), err) catch break;
        };
    }
}

// accept client in a loop creating a thread per client
fn serve(ctx: Ctx) !void {
    var server = try ctx.local_addr.listen(.{ .reuse_port = true });
    log.info("Listening on {} and serving {s}/", .{ ctx.local_addr, ctx.root });

    // setup thread pool
    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = ctx.allocator });
    defer pool.deinit();

    // accept client in a loop, if all threads are occupied
    // prevent new client from waiting (close their connection, sending ClientQueueIsFull)
    var client_counter = std.atomic.Value(u8).init(0);
    while (true) {
        const client = try server.accept();
        if (client_counter.load(.seq_cst) == pool.threads.len) {
            defer client.stream.close();
            Metadata.sendError(client.stream.writer(), error.ClientQueueIsFull) catch continue;
            continue;
        }
        try pool.spawn(clientLoop, .{ ctx, client, &client_counter });
        log.info("New client on {} [{d}/{d}]", .{
            client.address,
            client_counter.fetchAdd(1, .seq_cst) + 1,
            pool.threads.len,
        });
    }
}

pub fn main() void {
    // setup allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) @panic("leak detected");
    const allocator = gpa.allocator();

    // parse arguments
    const args = Cli.parse(allocator) catch {
        return Cli.usage("zfs") catch return;
    };
    defer args.deinit();
    if (args.positionals.len != 1) {
        return Cli.usage(args.executable_name) catch return;
    }

    // parse address
    const ip = args.options.bind;
    const port = std.fmt.parseUnsigned(u16, args.positionals[0], 10) catch |e| {
        return print("parseUnsigned({s}): {s}", .{ args.positionals[0], @errorName(e) });
    };
    const addr = net.Address.parseIp(ip, port) catch |e| {
        return print("parseIp({s}:{d}): {s}\n", .{ ip, port, @errorName(e) });
    };

    // check given path and if directory remove trailing / from path
    const stat = std.fs.cwd().statFile(args.options.directory) catch |e| {
        return print("stat({s}): {s}\n", .{ args.options.directory, @errorName(e) });
    };
    if (stat.kind != .directory) return print("{s}: is not a directory\n", .{args.options.directory});
    const dir = mem.trimRight(u8, args.options.directory, "/");

    // setup context and start the server
    const ctx = Ctx{ .root = dir, .local_addr = addr, .allocator = allocator };
    serve(ctx) catch |e| {
        return log.err("serve(): {s}", .{@errorName(e)});
    };
}
