const std = @import("std");

pub const key_size = 16;
pub const nonce_size = 0;
pub const tag_size = 0;

pub fn encrypt(ciphertext: []u8, _: []u8, _: []const u8, _: []const u8, _: []const u8, key: []const u8) void {
    for (ciphertext, 0..) |*b, i| {
        b.* ^= key[i % key.len];
    }
}

pub fn decrypt(plaintext: []u8, _: []const u8, _: []const u8, _: []const u8, _: []const u8, key: []const u8) void {
    for (plaintext, 0..) |*b, i| {
        b.* ^= key[i % key.len];
    }
}

test "xor encrypt/decrypt" {
    const message = "Hello World!";
    const key = "secret";
    var buffer: [12]u8 = undefined;
    @memcpy(&buffer, message);

    encrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, &[_]u8{}, key);
    
    // XORing twice with same key should return original
    decrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, &[_]u8{}, key);
    
    try std.testing.expectEqualStrings(message, &buffer);
}
