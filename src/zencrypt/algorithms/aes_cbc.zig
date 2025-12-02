const std = @import("std");

pub const nonce_size = 16;
pub const tag_size = 0;
pub const block_size = 16;

pub fn encrypt(ciphertext: []u8, _: []u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    if (key.len == 16) {
        const ctx = std.crypto.core.aes.Aes128.initEnc(key[0..16].*);
        applyCbc(16, ctx, nonce[0..16].*, ciphertext);
    } else {
        const ctx = std.crypto.core.aes.Aes256.initEnc(key[0..32].*);
        applyCbc(16, ctx, nonce[0..16].*, ciphertext);
    }
}

pub fn decrypt(plaintext: []u8, _: []const u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    if (key.len == 16) {
        const ctx = std.crypto.core.aes.Aes128.initDec(key[0..16].*);
        applyCbcDecrypt(16, ctx, nonce[0..16].*, plaintext);
    } else {
        const ctx = std.crypto.core.aes.Aes256.initDec(key[0..32].*);
        applyCbcDecrypt(16, ctx, nonce[0..16].*, plaintext);
    }
}

fn applyCbc(comptime block_len: usize, ctx: anytype, iv: [block_len]u8, data: []u8) void {
    var vec = iv;
    var i: usize = 0;
    while (i < data.len) : (i += block_len) {
        const block = data[i..][0..block_len];
        for (block, 0..) |*b, j| b.* ^= vec[j];
        ctx.encrypt(block, block);
        vec = block.*;
    }
}

fn applyCbcDecrypt(comptime block_len: usize, ctx: anytype, iv: [block_len]u8, data: []u8) void {
    var vec = iv;
    var i: usize = 0;
    while (i < data.len) : (i += block_len) {
        const block = data[i..][0..block_len];
        const next_vec = block.*;
        ctx.decrypt(block, block);
        for (block, 0..) |*b, j| b.* ^= vec[j];
        vec = next_vec;
    }
}

test "aes-cbc 128 encrypt/decrypt" {
    const key = "0123456789012345"; // 16 bytes
    const nonce = "0123456789012345"; // 16 bytes
    const message = "0123456789012345"; // 16 bytes, 1 block

    var buffer: [16]u8 = undefined;
    @memcpy(&buffer, message);

    encrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    
    try std.testing.expect(!std.mem.eql(u8, message, &buffer));

    decrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    
    try std.testing.expectEqualStrings(message, &buffer);
}

test "aes-cbc 256 encrypt/decrypt" {
    const key = "01234567890123450123456789012345"; // 32 bytes
    const nonce = "0123456789012345"; // 16 bytes
    const message = "01234567890123450123456789012345"; // 32 bytes, 2 blocks

    var buffer: [32]u8 = undefined;
    @memcpy(&buffer, message);

    encrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    decrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    
    try std.testing.expectEqualStrings(message, &buffer);
}