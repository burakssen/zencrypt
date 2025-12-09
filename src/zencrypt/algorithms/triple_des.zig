const std = @import("std");
const utils = @import("utils/triple_des.zig");
const common = @import("common.zig");

const TripleDes = @This();

const Core = common.BlockCipher(8);

pub fn encrypt(_: *TripleDes, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    if (key.len != 24) return error.InvalidKeyLength; // 3DES requires 24 bytes (192 bits)

    // Generate subkeys for all 3 keys
    const k1 = try utils.des.keyToU64(key[0..8]);
    const k2 = try utils.des.keyToU64(key[8..16]);
    const k3 = try utils.des.keyToU64(key[16..24]);

    const sk1 = utils.des.generateSubkeys(k1);
    const sk2 = utils.des.generateSubkeys(k2);
    const sk3 = utils.des.generateSubkeys(k3);

    const ctx = TripleDesContext{ .sk1 = sk1, .sk2 = sk2, .sk3 = sk3 };
    try Core.encrypt(reader, writer, ctx, encryptBlockFn);
}

pub fn decrypt(_: *TripleDes, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    if (key.len != 24) return error.InvalidKeyLength;

    const k1 = try utils.des.keyToU64(key[0..8]);
    const k2 = try utils.des.keyToU64(key[8..16]);
    const k3 = try utils.des.keyToU64(key[16..24]);

    const sk1 = utils.des.generateSubkeys(k1);
    const sk2 = utils.des.generateSubkeys(k2);
    const sk3 = utils.des.generateSubkeys(k3);

    const ctx = TripleDesContext{ .sk1 = sk1, .sk2 = sk2, .sk3 = sk3 };
    try Core.decrypt(reader, writer, ctx, decryptBlockFn);
}

const TripleDesContext = struct {
    sk1: [16]u48,
    sk2: [16]u48,
    sk3: [16]u48,
};

fn encryptBlockFn(ctx: TripleDesContext, block: *[8]u8) void {
    var b: u64 = 0;
    for (block, 0..) |byte, i| b |= @as(u64, byte) << @intCast(56 - i * 8);
    const enc = utils.processBlock3DES(b, ctx.sk1, ctx.sk2, ctx.sk3, false);
    for (0..8) |i| block[i] = @intCast((enc >> @intCast(56 - i * 8)) & 0xFF);
}

fn decryptBlockFn(ctx: TripleDesContext, block: *[8]u8) void {
    var b: u64 = 0;
    for (block, 0..) |byte, i| b |= @as(u64, byte) << @intCast(56 - i * 8);
    const dec = utils.processBlock3DES(b, ctx.sk1, ctx.sk2, ctx.sk3, true);
    for (0..8) |i| block[i] = @intCast((dec >> @intCast(56 - i * 8)) & 0xFF);
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
