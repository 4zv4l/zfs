const std = @import("std");
const log = std.log;
const utils = @import("utils.zig");
const Md5 = std.crypto.hash.Md5;

// struct used to send the client the info before sending the file
pub const Metadata = extern struct {
    md5sum: [Md5.digest_length]u8,
    filesize: u64,

    pub fn getMetadataFile(file: std.fs.File) !Metadata {
        // get file size
        const filestats = try file.stat();
        log.info("Got stat from file: {}", .{filestats});

        // get md5sum from file
        var fbin = std.io.bufferedReader(file.reader());
        var freader = fbin.reader();
        const md5digest = try utils.md5sum(&freader);
        log.info("Got md5hash from file: '{}'", .{std.fmt.fmtSliceHexLower(&md5digest)});

        return .{ .md5sum = md5digest, .filesize = filestats.size };
    }
};
