const std = @import("std");

const Xor = @This();

allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Xor {
    return Xor{
        .allocator = allocator,
    };
}

pub fn encrypt(_: *Xor, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    var key_index: usize = 0;
    if (key.len == 0) return; // Guard against mod by zero if key is empty

    while (true) {
        // Updated from takeByte to readByte
        const byte = reader.takeByte() catch |err| {
            if (err == error.EndOfStream) break;
            return err;
        };
        const encrypted_byte = byte ^ key[key_index];
        try writer.writeByte(encrypted_byte);
        key_index = (key_index + 1) % key.len;
    }
}

pub fn decrypt(self: *Xor, reader: anytype, writer: anytype, key: []const u8) !void {
    // XOR decryption is identical to encryption
    return self.encrypt(reader, writer, key);
}
