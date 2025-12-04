const std = @import("std");

const common = @import("common/des.zig");

const Des = @This();

pub fn encrypt(_: *Des, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    const key64 = try common.keyToU64(key);
    const subkeys = common.generateSubkeys(key64);

    var buffer: [8]u8 = undefined;

    while (true) {
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const bytes_read = reader.stream(&buffer_writer, .limited(8)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (bytes_read == 0) {
            @memset(&buffer, 8);
            var block: u64 = 0;
            for (buffer, 0..) |byte, i| block |= @as(u64, byte) << @intCast(56 - i * 8);

            const encrypted = common.processBlock(block, subkeys, false);
            for (0..8) |i| try writer.writeByte(@intCast((encrypted >> @intCast(56 - i * 8)) & 0xFF));

            break;
        }

        if (bytes_read < 8) {
            const pad_val: u8 = @intCast(8 - bytes_read);
            for (bytes_read..8) |i| {
                buffer[i] = pad_val;
            }
        }

        var block: u64 = 0;
        for (buffer, 0..) |byte, i| {
            block |= @as(u64, byte) << @intCast(56 - i * 8);
        }

        const encrypted = common.processBlock(block, subkeys, false);

        for (0..8) |i| {
            const byte: u8 = @intCast((encrypted >> @intCast(56 - i * 8)) & 0xFF);
            try writer.writeByte(byte);
        }

        if (bytes_read < 8) break;
    }
}

pub fn decrypt(_: *Des, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    const key64 = try common.keyToU64(key);
    const subkeys = common.generateSubkeys(key64);

    var prev_block: ?[8]u8 = null;
    var buffer: [8]u8 = undefined;

    while (true) {
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const amt = reader.stream(&buffer_writer, .limited(8)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (amt == 0) break;
        if (amt != 8) return error.InvalidCiphertextLength;

        var block: u64 = 0;
        for (buffer, 0..) |byte, i| {
            block |= @as(u64, byte) << @intCast(56 - i * 8);
        }

        const decrypted = common.processBlock(block, subkeys, true);

        var current_decrypted: [8]u8 = undefined;
        for (0..8) |i| {
            current_decrypted[i] = @intCast((decrypted >> @intCast(56 - i * 8)) & 0xFF);
        }

        if (prev_block) |prev| {
            try writer.writeAll(&prev);
        }

        prev_block = current_decrypted;
    }

    if (prev_block) |last| {
        const pad_val = last[7];
        if (pad_val == 0 or pad_val > 8) return error.InvalidPadding;

        for (8 - pad_val..8) |i| {
            if (last[i] != pad_val) return error.InvalidPadding;
        }

        try writer.writeAll(last[0 .. 8 - pad_val]);
    }
}

test "DES encryption/decryption" {
    const allocator = std.testing.allocator;

    var des = Des{};

    const key = "DESCRYPT".*;
    const plaintext = "Hello!!!";

    var input_stream: std.Io.Reader = .fixed(plaintext);
    var encrypted_buffer: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_buffer.deinit();

    try des.encrypt(&input_stream, &encrypted_buffer.writer, &key);

    var encrypted_stream: std.Io.Reader = .fixed(encrypted_buffer.written());
    var decrypted_buffer: std.Io.Writer.Allocating = .init(allocator);
    defer decrypted_buffer.deinit();

    try des.decrypt(&encrypted_stream, &decrypted_buffer.writer, &key);

    try std.testing.expectEqualStrings(plaintext, decrypted_buffer.written());
}
