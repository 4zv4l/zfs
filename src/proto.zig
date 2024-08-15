const Md5 = @import("std").crypto.hash.Md5;

// struct used to send the client the info before sending the file
pub const Metadata = extern struct { md5sum: [Md5.digest_length]u8, filesize: u64 };
