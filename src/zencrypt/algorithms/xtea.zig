const std = @import("std");

pub const key_size = 16;
pub const nonce_size = 8;
pub const tag_size = 0;
pub const block_size = 8;

pub fn encrypt(ciphertext: []u8, _: []u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    var k: [4]u32 = undefined;
    @memcpy(std.mem.asBytes(&k), key[0..16]);

    var iv: [8]u8 = undefined;
    @memcpy(&iv, nonce);

    var i: usize = 0;
    while (i < ciphertext.len) : (i += 8) {
        const block = ciphertext[i..][0..8];
        // CBC Mode
        for (block, 0..) |*b, j| b.* ^= iv[j];

        // XTEA Encrypt Block (in-place)
        var v: [2]u32 = undefined;
        v[0] = std.mem.readInt(u32, block[0..4], .little);
        v[1] = std.mem.readInt(u32, block[4..8], .little);

        encryptBlock(&v, k);

        std.mem.writeInt(u32, block[0..4], v[0], .little);
        std.mem.writeInt(u32, block[4..8], v[1], .little);

        // Update IV
        @memcpy(&iv, block);
    }
}

pub fn decrypt(plaintext: []u8, _: []const u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    var k: [4]u32 = undefined;
    @memcpy(std.mem.asBytes(&k), key[0..16]);

    var iv: [8]u8 = undefined;
    @memcpy(&iv, nonce);

    var i: usize = 0;
    while (i < plaintext.len) : (i += 8) {
        const block = plaintext[i..][0..8];
        const next_iv = block.*;

        // XTEA Decrypt
        var v: [2]u32 = undefined;
        v[0] = std.mem.readInt(u32, block[0..4], .little);
        v[1] = std.mem.readInt(u32, block[4..8], .little);

        decryptBlock(&v, k);

        std.mem.writeInt(u32, block[0..4], v[0], .little);
        std.mem.writeInt(u32, block[4..8], v[1], .little);

        for (block, 0..) |*b, j| b.* ^= iv[j];

        iv = next_iv;
    }
}

fn encryptBlock(v: *[2]u32, key: [4]u32) void {
    var v0 = v[0];
    var v1 = v[1];
    var sum: u32 = 0;
    const delta: u32 = 0x9E3779B9;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        v0 +%= (((v1 << 4) ^ (v1 >> 5)) +% v1) ^ (sum +% key[sum & 3]);
        sum +%= delta;
        v1 +%= (((v0 << 4) ^ (v0 >> 5)) +% v0) ^ (sum +% key[(sum >> 11) & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

fn decryptBlock(v: *[2]u32, key: [4]u32) void {
    var v0 = v[0];
    var v1 = v[1];
    var sum: u32 = 0xC6EF3720;
    const delta: u32 = 0x9E3779B9;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        v1 -%= (((v0 << 4) ^ (v0 >> 5)) +% v0) ^ (sum +% key[(sum >> 11) & 3]);
        sum -%= delta;
        v0 -%= (((v1 << 4) ^ (v1 >> 5)) +% v1) ^ (sum +% key[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

test "xtea encrypt/decrypt" {
    const key_bytes = "0123456789012345"; // 16 bytes
    const nonce = "12345678"; // 8 bytes
    const message = "12345678"; // 8 bytes, 1 block

    var buffer: [8]u8 = undefined;
    @memcpy(&buffer, message);

    encrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key_bytes);
    
    // Ensure it actually changed
    try std.testing.expect(!std.mem.eql(u8, message, &buffer));

    decrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key_bytes);
    
    try std.testing.expectEqualStrings(message, &buffer);
}

test "xtea multi-block" {
    const key_bytes = "0123456789012345";
    const nonce = "12345678";
    const message = "1234567812345678"; // 16 bytes, 2 blocks

    var buffer: [16]u8 = undefined;
    @memcpy(&buffer, message);

    encrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key_bytes);
    decrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key_bytes);

    try std.testing.expectEqualStrings(message, &buffer);
}