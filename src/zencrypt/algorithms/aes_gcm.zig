const std = @import("std");
const common = @import("common.zig");
const AesGcm = @This();

pub const AesGcmType = enum {
    AesGcm128,
    AesGcm256,
};

// Standard chunk size (4KB is efficient for disk I/O)
const CHUNK_SIZE = 4096;
const TAG_SIZE = 16;
const NONCE_SIZE = 12;

allocator: std.mem.Allocator,
aes_gcm_type: AesGcmType,

pub fn init(allocator: std.mem.Allocator, aes_gcm_type: AesGcmType) AesGcm {
    return AesGcm{
        .allocator = allocator,
        .aes_gcm_type = aes_gcm_type,
    };
}

const Core = common.AeadStreamCipher(NONCE_SIZE, TAG_SIZE, CHUNK_SIZE);

pub fn encrypt(self: *AesGcm, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    // Validate key length first
    switch (self.aes_gcm_type) {
        .AesGcm128 => if (key.len != 16) return error.InvalidKeyLength,
        .AesGcm256 => if (key.len != 32) return error.InvalidKeyLength,
    }

    const ctx = Context{ .key = key, .type = self.aes_gcm_type };
    try Core.encrypt(reader, writer, ctx, computeNonce, encryptChunk);
}

pub fn decrypt(self: *AesGcm, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
     switch (self.aes_gcm_type) {
        .AesGcm128 => if (key.len != 16) return error.InvalidKeyLength,
        .AesGcm256 => if (key.len != 32) return error.InvalidKeyLength,
    }

    const ctx = Context{ .key = key, .type = self.aes_gcm_type };
    try Core.decrypt(reader, writer, ctx, computeNonce, decryptChunk);
}

const Context = struct {
    key: []const u8,
    type: AesGcmType,
};

fn computeNonce(base_nonce: [NONCE_SIZE]u8, counter: u32) [NONCE_SIZE]u8 {
    var new_nonce = base_nonce;
    const last_part = std.mem.readInt(u32, base_nonce[8..12], .big);
    // Use wrapping addition
    const updated = last_part +% counter;
    std.mem.writeInt(u32, new_nonce[8..12], updated, .big);
    return new_nonce;
}

fn encryptChunk(ctx: Context, nonce: [NONCE_SIZE]u8, plaintext: []const u8, ciphertext: []u8, tag: *[TAG_SIZE]u8) void {
    switch (ctx.type) {
        .AesGcm128 => std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(ciphertext, tag, plaintext, "a", nonce, ctx.key[0..16].*),
        .AesGcm256 => std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, tag, plaintext, "a", nonce, ctx.key[0..32].*),
    }
}

fn decryptChunk(ctx: Context, nonce: [NONCE_SIZE]u8, ciphertext: []const u8, tag: [TAG_SIZE]u8, plaintext: []u8) !void {
    switch (ctx.type) {
        .AesGcm128 => try std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(plaintext, ciphertext, tag, "a", nonce, ctx.key[0..16].*),
        .AesGcm256 => try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext, ciphertext, tag, "a", nonce, ctx.key[0..32].*),
    }
}

test "Streaming Chunked GCM" {
    const allocator = std.testing.allocator;
    var gcm = AesGcm.init(allocator, .AesGcm256);
    const key = "12345678901234567890123456789012";

    // Create data larger than one chunk (4096) to test loop
    const input_data = "A" ** 5000;

    // Encrypt
    var in_stream: std.Io.Reader = .fixed(input_data);
    var out_list: std.Io.Writer.Allocating = .init(allocator);
    defer out_list.deinit();

    try gcm.encrypt(&in_stream, &out_list.writer, key);

    // Decrypt
    var dec_in_stream: std.Io.Reader = .fixed(out_list.written());
    var dec_out_list: std.Io.Writer.Allocating = .init(allocator);
    defer dec_out_list.deinit();

    try gcm.decrypt(&dec_in_stream, &dec_out_list.writer, key);
    try std.testing.expectEqualStrings(input_data, dec_out_list.written());
}
