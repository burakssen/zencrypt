const std = @import("std");
const common = @import("common.zig");
const ChaCha20 = @This();

const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const CHUNK_SIZE = 4096;

allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) ChaCha20 {
    return ChaCha20{
        .allocator = allocator,
    };
}

const Core = common.AeadStreamCipher(NONCE_SIZE, TAG_SIZE, CHUNK_SIZE);

pub fn encrypt(self: *ChaCha20, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    const ctx = Context{ .key = key };
    var core = Core.init(self.allocator);
    try core.encrypt(reader, writer, ctx, computeNonce, encryptChunk);
}

pub fn decrypt(self: *ChaCha20, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    const ctx = Context{ .key = key };
    var core = Core.init(self.allocator);
    try core.decrypt(reader, writer, ctx, computeNonce, decryptChunk);
}

const Context = struct {
    key: []const u8,
};

fn computeNonce(base_nonce: [NONCE_SIZE]u8, counter: u32) [NONCE_SIZE]u8 {
    var new_nonce = base_nonce;
    const last_part = std.mem.readInt(u32, base_nonce[8..12], .big);
    const updated = last_part +% counter;
    std.mem.writeInt(u32, new_nonce[8..12], updated, .big);
    return new_nonce;
}

fn encryptChunk(ctx: Context, nonce: [NONCE_SIZE]u8, plaintext: []const u8, ciphertext: []u8, tag: *[TAG_SIZE]u8) void {
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        ciphertext,
        tag,
        plaintext,
        "a",
        nonce,
        ctx.key[0..32].*,
    );
}

fn decryptChunk(ctx: Context, nonce: [NONCE_SIZE]u8, ciphertext: []const u8, tag: [TAG_SIZE]u8, plaintext: []u8) !void {
    try std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        plaintext,
        ciphertext,
        tag,
        "a",
        nonce,
        ctx.key[0..32].*,
    );
}
