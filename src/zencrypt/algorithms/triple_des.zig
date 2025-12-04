const std = @import("std");

const common = @import("common/des.zig");

const TripleDes = @This();

/// Triple DES Block processing (EDE)
/// Encrypt: E(k1) -> D(k2) -> E(k3)
/// Decrypt: D(k3) -> E(k2) -> D(k1)
fn processBlock3DES(block: u64, subkeys1: [16]u48, subkeys2: [16]u48, subkeys3: [16]u48, decrypting: bool) u64 {
    if (!decrypting) {
        // Encrypt: E1 -> D2 -> E3
        var b = common.processBlock(block, subkeys1, false);
        b = common.processBlock(b, subkeys2, true);
        b = common.processBlock(b, subkeys3, false);
        return b;
    } else {
        // Decrypt: D3 -> E2 -> D1
        var b = common.processBlock(block, subkeys3, true);
        b = common.processBlock(b, subkeys2, false);
        b = common.processBlock(b, subkeys1, true);
        return b;
    }
}

pub fn encrypt(_: *TripleDes, reader: anytype, writer: anytype, key: []const u8) !void {
    if (key.len != 24) return error.InvalidKeyLength; // 3DES requires 24 bytes (192 bits)

    // Generate subkeys for all 3 keys
    const k1 = try common.keyToU64(key[0..8]);
    const k2 = try common.keyToU64(key[8..16]);
    const k3 = try common.keyToU64(key[16..24]);

    const sk1 = common.generateSubkeys(k1);
    const sk2 = common.generateSubkeys(k2);
    const sk3 = common.generateSubkeys(k3);

    var buffer: [8]u8 = undefined;

    while (true) {
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const bytes_read = reader.stream(&buffer_writer, .limited(8)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (bytes_read == 0) {
            // Apply Padding (PKCS#7) for empty last block
            @memset(&buffer, 8);
            var block: u64 = 0;
            for (buffer, 0..) |byte, i| block |= @as(u64, byte) << @intCast(56 - i * 8);

            const encrypted = processBlock3DES(block, sk1, sk2, sk3, false);
            for (0..8) |i| try writer.writeByte(@intCast((encrypted >> @intCast(56 - i * 8)) & 0xFF));

            break;
        }

        if (bytes_read < 8) {
            // Apply Padding (PKCS#7)
            const pad_val: u8 = @intCast(8 - bytes_read);
            for (bytes_read..8) |i| {
                buffer[i] = pad_val;
            }
        }

        var block: u64 = 0;
        for (buffer, 0..) |byte, i| {
            block |= @as(u64, byte) << @intCast(56 - i * 8);
        }

        // 3DES Encrypt
        const encrypted = processBlock3DES(block, sk1, sk2, sk3, false);

        for (0..8) |i| {
            const byte: u8 = @intCast((encrypted >> @intCast(56 - i * 8)) & 0xFF);
            try writer.writeByte(byte);
        }

        if (bytes_read < 8) break;
    }
}

pub fn decrypt(_: *TripleDes, reader: anytype, writer: anytype, key: []const u8) !void {
    if (key.len != 24) return error.InvalidKeyLength;

    const k1 = try common.keyToU64(key[0..8]);
    const k2 = try common.keyToU64(key[8..16]);
    const k3 = try common.keyToU64(key[16..24]);

    const sk1 = common.generateSubkeys(k1);
    const sk2 = common.generateSubkeys(k2);
    const sk3 = common.generateSubkeys(k3);

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

        // 3DES Decrypt
        const decrypted = processBlock3DES(block, sk1, sk2, sk3, true);

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
        // Validate and Remove Padding (PKCS#7)
        const pad_val = last[7];
        if (pad_val == 0 or pad_val > 8) return error.InvalidPadding;

        for (8 - pad_val..8) |i| {
            if (last[i] != pad_val) return error.InvalidPadding;
        }

        try writer.writeAll(last[0 .. 8 - pad_val]);
    }
}

test "TripleDES encryption/decryption" {
    const allocator = std.testing.allocator;

    var tdes = TripleDes{};

    // 24-byte key (192 bits)
    const key = "12345678" ++ "87654321" ++ "12341234";
    const plaintext = "Hello Triple DES world!!";

    // Setup streams
    var input_stream: std.Io.Reader = .fixed(plaintext);
    var encrypted_list: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_list.deinit();

    // Encrypt
    try tdes.encrypt(&input_stream, &encrypted_list.writer, key);

    // Setup decryption streams
    var encrypted_stream: std.Io.Reader = .fixed(encrypted_list.written());
    var decrypted_list: std.Io.Writer.Allocating = .init(allocator);
    defer decrypted_list.deinit();

    // Decrypt
    try tdes.decrypt(&encrypted_stream, &decrypted_list.writer, key);

    try std.testing.expectEqualStrings(plaintext, decrypted_list.written());
}
