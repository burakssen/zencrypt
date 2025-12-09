const std = @import("std");
const utils = @import("utils/xtea.zig");
const common = @import("common.zig");

const Xtea = @This();

allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Xtea {
    return Xtea{
        .allocator = allocator,
    };
}

const Core = common.BlockCipher(8);

pub fn encrypt(self: *Xtea, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    const key_words = try utils.keyToWords(key);
    const ctx = XteaContext{ .key_words = key_words };
    var core = Core.init(self.allocator);
    try core.encrypt(reader, writer, ctx, encryptBlockFn);
}

pub fn decrypt(self: *Xtea, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    const key_words = try utils.keyToWords(key);
    const ctx = XteaContext{ .key_words = key_words };
    var core = Core.init(self.allocator);
    try core.decrypt(reader, writer, ctx, decryptBlockFn);
}

const XteaContext = struct {
    key_words: [4]u32,
};

fn encryptBlockFn(ctx: XteaContext, block: *[8]u8) void {
    var b: u64 = 0;
    for (block, 0..) |byte, i| b |= @as(u64, byte) << @intCast(56 - i * 8);
    const enc = utils.encipher(b, ctx.key_words);
    for (0..8) |i| block[i] = @intCast((enc >> @intCast(56 - i * 8)) & 0xFF);
}

fn decryptBlockFn(ctx: XteaContext, block: *[8]u8) void {
    var b: u64 = 0;
    for (block, 0..) |byte, i| b |= @as(u64, byte) << @intCast(56 - i * 8);
    const dec = utils.decipher(b, ctx.key_words);
    for (0..8) |i| block[i] = @intCast((dec >> @intCast(56 - i * 8)) & 0xFF);
}

test "XTEA encryption/decryption" {
    const allocator = std.testing.allocator;
    var xtea = Xtea.init(allocator);

    // XTEA Key must be 16 bytes
    const key = "1234567890123456";
    const plaintext = "Hello XTEA World!!!";

    var input_stream: std.Io.Reader = .fixed(plaintext);
    var encrypted_list: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_list.deinit();

    try xtea.encrypt(&input_stream, &encrypted_list.writer, key);
    var encrypted_stream: std.Io.Reader = .fixed(encrypted_list.written());
    var decrypted_list: std.Io.Writer.Allocating = .init(allocator);
    defer decrypted_list.deinit();

    try xtea.decrypt(&encrypted_stream, &decrypted_list.writer, key);
    try std.testing.expectEqualStrings(plaintext, decrypted_list.written());
}
