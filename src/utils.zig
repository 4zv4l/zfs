const std = @import("std");
const log = std.log;
const Md5 = std.crypto.hash.Md5;
const Metadata = @import("proto.zig").Metadata;

// calculate the md5sum from the reader
pub fn md5sum(reader: anytype) ![Md5.digest_length]u8 {
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
pub fn sendError(writer: anytype, err: anyerror) !void {
    const strerror = @errorName(err);
    log.warn("{s}", .{strerror});
    _ = try writer.writeStruct(Metadata{
        .md5sum = .{0} ** Md5.digest_length,
        .filesize = strerror.len,
    });
    _ = try writer.write(strerror);
}

// modify the given path to remove the '../'
pub fn sanitizePath(path: []u8) []const u8 {
    var pathbuff: [std.fs.max_path_bytes]u8 = undefined;
    const max_len = @min(pathbuff.len, path.len);
    @memcpy(pathbuff[0..max_len], path[0..max_len]);

    const final_size = std.mem.replacementSize(u8, path[0..max_len], "../", "");
    _ = std.mem.replace(u8, pathbuff[0..max_len], "../", "", path[0..final_size]);

    return path[0..final_size];
}
