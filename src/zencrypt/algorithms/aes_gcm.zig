const std = @import("std");

pub const nonce_size = std.crypto.aead.aes_gcm.Aes128Gcm.nonce_length;
pub const tag_size = std.crypto.aead.aes_gcm.Aes128Gcm.tag_length;

pub fn encrypt(ciphertext: []u8, tag: []u8, message: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) void {
    const tag_array: *[16]u8 = @ptrCast(tag.ptr);
    if (key.len == 16) {
        std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(ciphertext, tag_array, message, ad, nonce[0..12].*, key[0..16].*);
    } else {
        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, tag_array, message, ad, nonce[0..12].*, key[0..32].*);
    }
}

pub fn decrypt(plaintext: []u8, tag: []const u8, ciphertext: []const u8, ad: []const u8, nonce: []const u8, key: []const u8) !void {
    const tag_array: *const [16]u8 = @ptrCast(tag.ptr);
    if (key.len == 16) {
        try std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(plaintext, ciphertext, tag_array.*, ad, nonce[0..12].*, key[0..16].*);
    } else {
        try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext, ciphertext, tag_array.*, ad, nonce[0..12].*, key[0..32].*);
    }
}

test "aes-gcm 128 encrypt/decrypt" {
    const key = "0123456789012345"; // 16 bytes
    const nonce = "012345678901"; // 12 bytes
    const message = "Hello GCM!";
    const ad = "meta";
    
    var ciphertext: [10]u8 = undefined;
    var tag: [16]u8 = undefined;
    var plaintext: [10]u8 = undefined;

    encrypt(&ciphertext, &tag, message, ad, nonce, key);
    
    try decrypt(&plaintext, &tag, &ciphertext, ad, nonce, key);
    
    try std.testing.expectEqualStrings(message, &plaintext);
}

test "aes-gcm 256 encrypt/decrypt" {
    const key = "01234567890123450123456789012345"; // 32 bytes
    const nonce = "012345678901"; // 12 bytes
    const message = "Hello GCM 256!";
    const ad = "meta";
    
    var ciphertext: [14]u8 = undefined;
    var tag: [16]u8 = undefined;
    var plaintext: [14]u8 = undefined;

    encrypt(&ciphertext, &tag, message, ad, nonce, key);
    
    try decrypt(&plaintext, &tag, &ciphertext, ad, nonce, key);
    
    try std.testing.expectEqualStrings(message, &plaintext);
}

test "aes-gcm auth failure" {
    const key = "0123456789012345";
    const nonce = "012345678901";
    const message = "Secret";
    
    var ciphertext: [6]u8 = undefined;
    var tag: [16]u8 = undefined;
    var plaintext: [6]u8 = undefined;

    encrypt(&ciphertext, &tag, message, "", nonce, key);
    
    // Tamper tag
    tag[0] ^= 0xFF;
    
    try std.testing.expectError(error.AuthenticationFailed, decrypt(&plaintext, &tag, &ciphertext, "", nonce, key));
}