const std = @import("std");
const utils = @import("utils/des.zig");
const common = @import("common.zig");

allocator: std.mem.Allocator,
const Des = @This();

const Core = common.BlockCipher(8);

pub fn init(allocator: std.mem.Allocator) Des {
    return Des{
        .allocator = allocator,
    };
}

pub fn encrypt(self: *Des, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    const key64 = try utils.keyToU64(key);
    const subkeys = utils.generateSubkeys(key64);
    const ctx = DesContext{ .subkeys = subkeys };
    var core = Core.init(self.allocator);
    try core.encrypt(reader, writer, ctx, encryptBlockFn);
}

pub fn decrypt(self: *Des, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    const key64 = try utils.keyToU64(key);
    const subkeys = utils.generateSubkeys(key64);
    const ctx = DesContext{ .subkeys = subkeys };
    var core = Core.init(self.allocator);
    try core.decrypt(reader, writer, ctx, decryptBlockFn);
}

const DesContext = struct {
    subkeys: [16]u48,
};

fn encryptBlockFn(ctx: DesContext, block: *[8]u8) void {
    var b: u64 = 0;
    for (block, 0..) |byte, i| b |= @as(u64, byte) << @intCast(56 - i * 8);
    const enc = utils.processBlock(b, ctx.subkeys, false);
    for (0..8) |i| block[i] = @intCast((enc >> @intCast(56 - i * 8)) & 0xFF);
}

fn decryptBlockFn(ctx: DesContext, block: *[8]u8) void {
    var b: u64 = 0;
    for (block, 0..) |byte, i| b |= @as(u64, byte) << @intCast(56 - i * 8);
    const dec = utils.processBlock(b, ctx.subkeys, true);
    for (0..8) |i| block[i] = @intCast((dec >> @intCast(56 - i * 8)) & 0xFF);
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
