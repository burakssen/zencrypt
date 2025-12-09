// blowfish.zig - Main Blowfish cipher implementation
const std = @import("std");
const utils = @import("utils/blowfish.zig");

const Blowfish = @This();
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Blowfish {
    return Blowfish{
        .allocator = allocator,
    };
}

pub fn encrypt(_: *Blowfish, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    if (key.len < 4 or key.len > 56) return error.InvalidKeyLength;

    var ctx = try utils.BlowfishContext.init(key);
    var buffer: [8]u8 = undefined;

    while (true) {
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const bytes_read = reader.stream(&buffer_writer, .limited(8)) catch |err|
            if (err == error.EndOfStream) 0 else return err;
        if (bytes_read == 0) {
            // End of stream, add full padding block (PKCS#7)
            @memset(&buffer, 8);
            const block = utils.bytesToBlock(&buffer);
            const encrypted = ctx.encryptBlock(block);
            try utils.writeBlock(writer, encrypted);
            break;
        }

        if (bytes_read < 8) {
            // Partial block, pad with (8 - bytes_read)
            const pad_val: u8 = @intCast(8 - bytes_read);
            for (bytes_read..8) |i| {
                buffer[i] = pad_val;
            }
        }

        const block = utils.bytesToBlock(&buffer);
        const encrypted = ctx.encryptBlock(block);
        try utils.writeBlock(writer, encrypted);

        if (bytes_read < 8) break;
    }
}

pub fn decrypt(_: *Blowfish, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    if (key.len < 4 or key.len > 56) return error.InvalidKeyLength;

    var ctx = try utils.BlowfishContext.init(key);
    var prev_block: ?[8]u8 = null;
    var buffer: [8]u8 = undefined;

    while (true) {
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const amt = reader.stream(&buffer_writer, .limited(8)) catch |err|
            if (err == error.EndOfStream) 0 else return err;
        if (amt == 0) break;
        if (amt != 8) return error.InvalidCiphertextLength;

        const block = utils.bytesToBlock(&buffer);
        const decrypted = ctx.decryptBlock(block);
        const current_decrypted = utils.blockToBytes(decrypted);

        // Write previous block if it exists (buffering for padding removal)
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

test "Blowfish encryption/decryption" {
    const allocator = std.testing.allocator;
    var bf = Blowfish.init(allocator);

    const key = "SecretKey123";
    const plaintext = "Hello Blowfish World!!!";

    var input_stream: std.Io.Reader = .fixed(plaintext);
    var encrypted_list: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_list.deinit();

    try bf.encrypt(&input_stream, &encrypted_list.writer, key);
    var encrypted_stream: std.Io.Reader = .fixed(encrypted_list.written());
    var decrypted_list: std.Io.Writer.Allocating = .init(allocator);
    defer decrypted_list.deinit();

    try bf.decrypt(&encrypted_stream, &decrypted_list.writer, key);

    try std.testing.expectEqualStrings(plaintext, decrypted_list.written());
}
