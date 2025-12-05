const std = @import("std");
const utils = @import("utils/xtea.zig");

const Xtea = @This();

allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Xtea {
    return Xtea{
        .allocator = allocator,
    };
}

pub fn encrypt(_: *Xtea, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    // XTEA requires a 128-bit key (16 bytes)
    const key_words = try utils.keyToWords(key);

    var buffer: [8]u8 = undefined;

    while (true) {
        // Read up to 8 bytes
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const bytes_read = reader.stream(&buffer_writer, .limited(8)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (bytes_read == 0) {
            // End of stream, add full padding block (PKCS#7)
            @memset(&buffer, 8);
            var block: u64 = 0;
            for (buffer, 0..) |byte, i| block |= @as(u64, byte) << @intCast(56 - i * 8);

            const encrypted = utils.encipher(block, key_words);
            for (0..8) |i| try writer.writeByte(@intCast((encrypted >> @intCast(56 - i * 8)) & 0xFF));
            break;
        }

        if (bytes_read < 8) {
            // Partial block, pad with (8 - bytes_read)
            const pad_val: u8 = @intCast(8 - bytes_read);
            for (bytes_read..8) |i| {
                buffer[i] = pad_val;
            }
        }

        // Pack bytes into u64 Big Endian
        var block: u64 = 0;
        for (buffer, 0..) |byte, i| {
            block |= @as(u64, byte) << @intCast(56 - i * 8);
        }

        const encrypted = utils.encipher(block, key_words);

        // Write resulting 8 bytes
        for (0..8) |i| {
            const byte: u8 = @intCast((encrypted >> @intCast(56 - i * 8)) & 0xFF);
            try writer.writeByte(byte);
        }

        if (bytes_read < 8) break;
    }
}

pub fn decrypt(_: *Xtea, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    const key_words = try utils.keyToWords(key);

    var prev_block: ?[8]u8 = null;
    var buffer: [8]u8 = undefined;

    while (true) {
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const amt = reader.stream(&buffer_writer, .limited(8)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (amt == 0) break;
        if (amt != 8) return error.InvalidCiphertextLength;

        // Pack
        var block: u64 = 0;
        for (buffer, 0..) |byte, i| {
            block |= @as(u64, byte) << @intCast(56 - i * 8);
        }

        const decrypted = utils.decipher(block, key_words);

        // Unpack
        var current_decrypted: [8]u8 = undefined;
        for (0..8) |i| {
            current_decrypted[i] = @intCast((decrypted >> @intCast(56 - i * 8)) & 0xFF);
        }

        // Write previous block if it exists (buffering to handle padding removal at the end)
        if (prev_block) |prev| {
            try writer.writeAll(&prev);
        }

        prev_block = current_decrypted;
    }

    // Handle PKCS#7 padding removal on the last block
    if (prev_block) |last| {
        const pad_val = last[7];
        if (pad_val == 0 or pad_val > 8) return error.InvalidPadding;

        // Verify padding integrity
        for (8 - pad_val..8) |i| {
            if (last[i] != pad_val) return error.InvalidPadding;
        }

        try writer.writeAll(last[0 .. 8 - pad_val]);
    }
}

test "XTEA encryption/decryption" {
    const allocator = std.testing.allocator;
    var xtea = Xtea.init(allocator);

    // XTEA Key must be 16 bytes
    const key = "1234567890123456";
    const plaintext = "Hello XTEA World!!!";

    var input_stream = std.io.fixedBufferStream(plaintext);
    var encrypted_list = std.ArrayList(u8).init(allocator);
    defer encrypted_list.deinit();

    try xtea.encrypt(input_stream.reader(), encrypted_list.writer(), key);

    var encrypted_stream = std.io.fixedBufferStream(encrypted_list.items);
    var decrypted_list = std.ArrayList(u8).init(allocator);
    defer decrypted_list.deinit();

    try xtea.decrypt(encrypted_stream.reader(), decrypted_list.writer(), key);

    try std.testing.expectEqualStrings(plaintext, decrypted_list.items);
}
