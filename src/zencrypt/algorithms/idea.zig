const std = @import("std");
const utils = @import("utils/idea.zig");
const common = @import("common.zig");

const Idea = @This();

const Core = common.BlockCipher(8);
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Idea {
    return Idea{
        .allocator = allocator,
    };
}

pub fn encrypt(self: *Idea, reader: anytype, writer: anytype, key: []const u8) !void {
    const key128 = try utils.keyToU128(key);
    const subkeys = utils.generateSubkeys(key128);
    const ctx = IdeaContext{ .subkeys = subkeys };
    var core = Core.init(self.allocator);
    try core.encrypt(reader, writer, ctx, encryptBlockFn);
}

pub fn decrypt(self: *Idea, reader: anytype, writer: anytype, key: []const u8) !void {
    const key128 = try utils.keyToU128(key);
    const enc_subkeys = utils.generateSubkeys(key128);
    const dec_subkeys = utils.invertSubkeys(enc_subkeys);
    const ctx = IdeaContext{ .subkeys = dec_subkeys };
    var core = Core.init(self.allocator);
    try core.decrypt(reader, writer, ctx, encryptBlockFn);
}

const IdeaContext = struct {
    subkeys: [52]u16,
};

fn encryptBlockFn(ctx: IdeaContext, block: *[8]u8) void {
    var b: u64 = 0;
    for (block, 0..) |byte, i| b |= @as(u64, byte) << @intCast(56 - i * 8);
    const enc = utils.processBlock(b, ctx.subkeys);
    for (0..8) |i| block[i] = @intCast((enc >> @intCast(56 - i * 8)) & 0xFF);
}

test "IDEA encryption/decryption" {
    const allocator = std.testing.allocator;

    var idea = Idea{};

    const key = "0123456789ABCDEF"; // 16 bytes
    const plaintext = "This is a secret message used to test IDEA algorithm.";

    var input_stream: std.Io.Reader = .fixed(plaintext);
    var encrypted_buffer: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_buffer.deinit();

    try idea.encrypt(&input_stream, &encrypted_buffer.writer, key);

    var encrypted_stream: std.Io.Reader = .fixed(encrypted_buffer.written());
    var decrypted_buffer: std.Io.Writer.Allocating = .init(allocator);
    defer decrypted_buffer.deinit();

    try idea.decrypt(&encrypted_stream, &decrypted_buffer.writer, key);

    try std.testing.expectEqualStrings(plaintext, decrypted_buffer.written());
}
