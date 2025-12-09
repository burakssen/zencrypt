// blowfish.zig - Main Blowfish cipher implementation
const std = @import("std");
const utils = @import("utils/blowfish.zig");
const common = @import("common.zig");

const Blowfish = @This();
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Blowfish {
    return Blowfish{
        .allocator = allocator,
    };
}

const Core = common.BlockCipher(8);

pub fn encrypt(_: *Blowfish, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    if (key.len < 4 or key.len > 56) return error.InvalidKeyLength;

    const ctx = try utils.BlowfishContext.init(key);
    try Core.encrypt(reader, writer, ctx, encryptBlockFn);
}

pub fn decrypt(_: *Blowfish, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    if (key.len < 4 or key.len > 56) return error.InvalidKeyLength;

    const ctx = try utils.BlowfishContext.init(key);
    try Core.decrypt(reader, writer, ctx, decryptBlockFn);
}

fn encryptBlockFn(ctx: utils.BlowfishContext, block: *[8]u8) void {
    const val = utils.bytesToBlock(block);
    const enc = ctx.encryptBlock(val);
    block.* = utils.blockToBytes(enc);
}

fn decryptBlockFn(ctx: utils.BlowfishContext, block: *[8]u8) void {
    const val = utils.bytesToBlock(block);
    const dec = ctx.decryptBlock(val);
    block.* = utils.blockToBytes(dec);
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
