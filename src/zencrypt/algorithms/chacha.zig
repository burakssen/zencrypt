const std = @import("std");

pub const key_size = 32;

pub const chacha20_nonce_size = 12;
pub const xchacha20_nonce_size = 24;
pub const poly1305_tag_size = 16;

pub fn encryptChaCha20(ciphertext: []u8, _: []u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    std.crypto.stream.chacha.ChaCha20IETF.xor(ciphertext, ciphertext, 0, key[0..32].*, nonce[0..12].*);
}

pub fn decryptChaCha20(plaintext: []u8, _: []const u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    std.crypto.stream.chacha.ChaCha20IETF.xor(plaintext, plaintext, 0, key[0..32].*, nonce[0..12].*);
}

pub fn encryptXChaCha20(ciphertext: []u8, _: []u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    std.crypto.stream.chacha.XChaCha20IETF.xor(ciphertext, ciphertext, 0, key[0..32].*, nonce[0..24].*);
}

pub fn decryptXChaCha20(plaintext: []u8, _: []const u8, _: []const u8, _: []const u8, nonce: []const u8, key: []const u8) void {
    std.crypto.stream.chacha.XChaCha20IETF.xor(plaintext, plaintext, 0, key[0..32].*, nonce[0..24].*);
}

pub fn encryptPoly1305(ciphertext: []u8, tag: []u8, message: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) void {
    const tag_array: *[16]u8 = @ptrCast(tag.ptr);
    std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(ciphertext, tag_array, message, ad, nonce[0..24].*, key[0..32].*);
}

pub fn decryptPoly1305(plaintext: []u8, tag: []const u8, ciphertext: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) !void {
    const tag_array: *const [16]u8 = @ptrCast(tag.ptr);
    try std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(plaintext, ciphertext, tag_array.*, ad, nonce[0..24].*, key[0..32].*);
}

test "chacha20 encrypt/decrypt" {
    const key = "01234567890123450123456789012345"; // 32 bytes
    const nonce = "012345678901"; // 12 bytes
    const message = "ChaCha20 msg";
    
    var buffer: [12]u8 = undefined;
    @memcpy(&buffer, message);
    
    encryptChaCha20(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    decryptChaCha20(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    
    try std.testing.expectEqualStrings(message, &buffer);
}

test "xchacha20 encrypt/decrypt" {
    const key = "01234567890123450123456789012345"; // 32 bytes
    const nonce = "012345678901234567890123"; // 24 bytes
    const message = "XChaCha20 msg";
    
    var buffer: [13]u8 = undefined;
    @memcpy(&buffer, message);
    
    encryptXChaCha20(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    decryptXChaCha20(&buffer, &[_]u8{}, &[_]u8{}, &[_]u8{}, nonce, key);
    
    try std.testing.expectEqualStrings(message, &buffer);
}

test "xchacha20poly1305 encrypt/decrypt" {
    const key = "01234567890123450123456789012345"; // 32 bytes
    const nonce = "012345678901234567890123"; // 24 bytes
    const message = "Poly1305 msg";
    const ad = "ad";
    
    var ciphertext: [12]u8 = undefined;
    var tag: [16]u8 = undefined;
    var plaintext: [12]u8 = undefined;
    
    encryptPoly1305(&ciphertext, &tag, message, ad, nonce, key);
    try decryptPoly1305(&plaintext, &tag, &ciphertext, ad, nonce, key);
    
    try std.testing.expectEqualStrings(message, &plaintext);
}