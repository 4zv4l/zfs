const std = @import("std");
const log = std.log;
const utils = @import("utils.zig");
const Md5 = std.crypto.hash.Md5;

// struct used to send the client the info before sending the file
pub const Metadata = extern struct {
    md5sum: [Md5.digest_length]u8,
    filesize: u64,

    pub fn sendFileMetadata(writer: anytype, file: std.fs.File) !void {
        // get file size
        const filestats = try file.stat();
        log.info("Got stat from file: {}", .{filestats});

        // get md5sum from file
        var fbin = std.io.bufferedReader(file.reader());
        var freader = fbin.reader();
        const md5digest = try utils.md5sum(&freader);
        log.info("Got md5hash from file: '{}'", .{std.fmt.fmtSliceHexLower(&md5digest)});

        const metadata = Metadata{
            .md5sum = md5digest,
            .filesize = filestats.size,
        };
        try writer.writeStruct(metadata);
        log.info(
            "Sent metadata: {{ hash: {s}, size: {d} }}",
            .{ std.fmt.fmtSliceHexLower(&metadata.md5sum), metadata.filesize },
        );
    }

    pub fn sendCmdMetadata(writer: anytype, data: []const u8) !void {
        var checksum: [Md5.digest_length]u8 = undefined;
        Md5.hash(data, &checksum, .{});
        const metadata = Metadata{ .md5sum = checksum, .filesize = data.len };
        try writer.writeStruct(metadata);
        log.info(
            "Sent metadata: {{ hash: {s}, size: {d} }}",
            .{ std.fmt.fmtSliceHexLower(&metadata.md5sum), metadata.filesize },
        );
    }

    // send error to client as 0 md5hash + err.len + err as string
    pub fn sendError(writer: anytype, err: anyerror) !void {
        const strerror = @errorName(err);
        log.warn("{s}", .{strerror});
        const metadata = Metadata{
            .md5sum = .{0} ** Md5.digest_length,
            .filesize = strerror.len,
        };
        _ = try writer.writeStruct(metadata);
        log.info(
            "Sent metadata: {{ hash: {s}, size: {d} }}",
            .{ std.fmt.fmtSliceHexLower(&metadata.md5sum), metadata.filesize },
        );
        _ = try writer.write(strerror);
    }
};
