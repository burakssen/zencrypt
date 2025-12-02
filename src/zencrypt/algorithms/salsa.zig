const std = @import("std");

pub const key_size = 32;
pub const nonce_size = 8;
pub const tag_size = 0;

pub fn encrypt(ciphertext: []u8, _: []u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    std.crypto.stream.salsa.Salsa20.xor(ciphertext, ciphertext, 0, key[0..32].*, nonce[0..8].*);
}

pub fn decrypt(plaintext: []u8, _: []const u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    std.crypto.stream.salsa.Salsa20.xor(plaintext, plaintext, 0, key[0..32].*, nonce[0..8].*);
}

test "salsa20 encrypt/decrypt" {
    const key = "01234567890123450123456789012345"; // 32 bytes
    const nonce = "12345678"; // 8 bytes
    const message = "Salsa Dance!";
    
    var buffer: [12]u8 = undefined;
    @memcpy(&buffer, message);
    
    encrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    
    try std.testing.expect(!std.mem.eql(u8, message, &buffer));
    
    decrypt(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    
    try std.testing.expectEqualStrings(message, &buffer);
}