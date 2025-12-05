const std = @import("std");
const Aes = @This();

const AesType = enum {
    Aes128,
    Aes256,
};

allocator: std.mem.Allocator,
aes_type: AesType,

pub fn init(allocator: std.mem.Allocator, aes_type: AesType) Aes {
    return Aes{
        .allocator = allocator,
        .aes_type = aes_type,
    };
}

pub fn encrypt(self: *Aes, reader: anytype, writer: anytype, key: []const u8) !void {
    switch (self.aes_type) {
        .Aes128 => try encryptInternal(reader, writer, std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128).init(key[0..16].*)),
        .Aes256 => try encryptInternal(reader, writer, std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256).init(key[0..32].*)),
    }
}

fn encryptInternal(reader: anytype, writer: anytype, aes: anytype) !void {
    var buffer: [16]u8 = undefined;

    while (true) {
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const bytes_read = reader.stream(&buffer_writer, .limited(16)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (bytes_read == 0) break;

        // Apply PKCS7 padding
        if (bytes_read < 16) {
            const pad_val: u8 = @intCast(16 - bytes_read);
            for (bytes_read..16) |i| {
                buffer[i] = pad_val;
            }
        }

        var block: [16]u8 = undefined;
        aes.encrypt(&block, &buffer);
        try writer.writeAll(&block);

        if (bytes_read < 16) break;
    }
}

pub fn decrypt(self: *Aes, reader: anytype, writer: anytype, key: []const u8) !void {
    switch (self.aes_type) {
        .Aes128 => try decryptInternal(reader, writer, std.crypto.core.aes.AesDecryptCtx(std.crypto.core.aes.Aes128).init(key[0..16].*)),
        .Aes256 => try decryptInternal(reader, writer, std.crypto.core.aes.AesDecryptCtx(std.crypto.core.aes.Aes256).init(key[0..32].*)),
    }
}

fn decryptInternal(reader: anytype, writer: anytype, aes: anytype) !void {
    var prev_block: ?[16]u8 = null;
    var buffer: [16]u8 = undefined;

    while (true) {
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const bytes_read = reader.stream(&buffer_writer, .limited(16)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (bytes_read == 0) {
            // Process the last block with padding removal
            if (prev_block) |last_block| {
                const pad_val = last_block[15];
                if (pad_val == 0 or pad_val > 16) return error.InvalidPadding;

                // Verify padding
                for (last_block[16 - pad_val .. 16]) |byte| {
                    if (byte != pad_val) return error.InvalidPadding;
                }

                const write_len = 16 - pad_val;
                try writer.writeAll(last_block[0..write_len]);
            }
            break;
        }

        // Decrypt current block
        var block: [16]u8 = undefined;
        aes.decrypt(&block, &buffer);

        // Write previous block if exists
        if (prev_block) |prev| {
            try writer.writeAll(&prev);
        }

        prev_block = block;

        if (bytes_read < 16) break;
    }
}
