const std = @import("std");

const algorithms = struct {
    pub const xor = @import("algorithms/xor.zig");
    pub const xtea = @import("algorithms/xtea.zig");
    pub const aes_cbc = @import("algorithms/aes_cbc.zig");
    pub const aes_gcm = @import("algorithms/aes_gcm.zig");
    pub const salsa = @import("algorithms/salsa.zig");
    pub const chacha = @import("algorithms/chacha.zig");
};

pub const Method = enum {
    None,
    Xor,
    Aes128Gcm,
    Aes256Gcm,
    Aes128Cbc,
    Aes256Cbc,
    Xtea,
    Salsa20,
    ChaCha20,
    XChaCha20,
    XChaCha20Poly1305,
};

pub fn keySize(method: Method) usize {
    return switch (method) {
        .None => 0,
        .Xor => algorithms.xor.key_size,
        .Aes128Gcm, .Aes128Cbc => 16,
        .Aes256Gcm, .Aes256Cbc => 32,
        .Xtea => algorithms.xtea.key_size,
        .Salsa20 => algorithms.salsa.key_size,
        .ChaCha20, .XChaCha20, .XChaCha20Poly1305 => algorithms.chacha.key_size,
    };
}

pub fn nonceSize(method: Method) usize {
    return switch (method) {
        .None, .Xor => algorithms.xor.nonce_size,
        .Aes128Cbc, .Aes256Cbc => algorithms.aes_cbc.nonce_size,
        .Xtea => algorithms.xtea.nonce_size,
        .Aes128Gcm, .Aes256Gcm => algorithms.aes_gcm.nonce_size,
        .Salsa20 => algorithms.salsa.nonce_size,
        .ChaCha20 => algorithms.chacha.chacha20_nonce_size,
        .XChaCha20, .XChaCha20Poly1305 => algorithms.chacha.xchacha20_nonce_size,
    };
}

pub fn tagSize(method: Method) usize {
    return switch (method) {
        .Aes128Gcm, .Aes256Gcm => algorithms.aes_gcm.tag_size,
        .XChaCha20Poly1305 => algorithms.chacha.poly1305_tag_size,
        else => 0,
    };
}

pub fn encrypt(
    allocator: std.mem.Allocator,
    method: Method,
    key: []const u8,
    message: []const u8,
    associated_data: []const u8,
) ![]u8 {
    if (method != .None and key.len != keySize(method)) return error.InvalidKeySize;
    
    const nonce_len = nonceSize(method);
    const tag_len = tagSize(method);
    var out_len = nonce_len + message.len + tag_len;
    
    const block_size: usize = switch (method) {
        .Aes128Cbc, .Aes256Cbc => algorithms.aes_cbc.block_size,
        .Xtea => algorithms.xtea.block_size,
        else => 0,
    };
    
    if (block_size > 0) {
        const padding = block_size - (message.len % block_size);
        out_len += padding;
    }

    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    // Generate Nonce
    if (nonce_len > 0) {
        std.crypto.random.bytes(out[0..nonce_len]);
    }
    const nonce = out[0..nonce_len];

    // Copy message to output buffer (after nonce)
    const msg_start = nonce_len;
    @memcpy(out[msg_start..msg_start+message.len], message);
    
    // Apply padding if needed
    if (block_size > 0) {
        const padding = block_size - (message.len % block_size);
        const pad_byte: u8 = @intCast(padding);
        for (out[msg_start+message.len..out.len - tag_len]) |*b| b.* = pad_byte;
    }

    const ciphertext = out[nonce_len..(out_len - tag_len)];
    const tag = out[(out_len - tag_len)..];

    switch (method) {
        .None => {},
        .Xor => algorithms.xor.encrypt(ciphertext, tag, message, associated_data, nonce, key),
        .Aes128Gcm, .Aes256Gcm => algorithms.aes_gcm.encrypt(ciphertext, tag, message, associated_data, nonce, key),
        .Aes128Cbc, .Aes256Cbc => algorithms.aes_cbc.encrypt(ciphertext, tag, message, associated_data, nonce, key),
        .Xtea => algorithms.xtea.encrypt(ciphertext, tag, message, associated_data, nonce, key),
        .Salsa20 => algorithms.salsa.encrypt(ciphertext, tag, message, associated_data, nonce, key),
        .ChaCha20 => algorithms.chacha.encryptChaCha20(ciphertext, tag, message, associated_data, nonce, key),
        .XChaCha20 => algorithms.chacha.encryptXChaCha20(ciphertext, tag, message, associated_data, nonce, key),
        .XChaCha20Poly1305 => algorithms.chacha.encryptPoly1305(ciphertext, tag, message, associated_data, nonce, key),
    }

    return out;
}

pub fn decrypt(
    allocator: std.mem.Allocator,
    method: Method,
    key: []const u8,
    data: []const u8,
    associated_data: []const u8,
) ![]u8 {
    if (method != .None and key.len != keySize(method)) return error.InvalidKeySize;
    
    const nonce_len = nonceSize(method);
    if (data.len < nonce_len) return error.InvalidCiphertext;

    const nonce = data[0..nonce_len];
    const ciphertext_and_tag = data[nonce_len..];
    
    const tag_len = tagSize(method);
    if (ciphertext_and_tag.len < tag_len) return error.InvalidCiphertext;

    const ciphertext_len = ciphertext_and_tag.len - tag_len;
    const ciphertext = ciphertext_and_tag[0..ciphertext_len];
    const tag = ciphertext_and_tag[ciphertext_len..];

    const out = try allocator.alloc(u8, ciphertext_len);
    errdefer allocator.free(out);
    @memcpy(out, ciphertext);

    switch (method) {
        .None => {},
        .Xor => algorithms.xor.decrypt(out, tag, ciphertext, associated_data, nonce, key),
        .Aes128Gcm, .Aes256Gcm => try algorithms.aes_gcm.decrypt(out, tag, ciphertext, associated_data, nonce, key),
        .Aes128Cbc, .Aes256Cbc => algorithms.aes_cbc.decrypt(out, tag, ciphertext, associated_data, nonce, key),
        .Xtea => algorithms.xtea.decrypt(out, tag, ciphertext, associated_data, nonce, key),
        .Salsa20 => algorithms.salsa.decrypt(out, tag, ciphertext, associated_data, nonce, key),
        .ChaCha20 => algorithms.chacha.decryptChaCha20(out, tag, ciphertext, associated_data, nonce, key),
        .XChaCha20 => algorithms.chacha.decryptXChaCha20(out, tag, ciphertext, associated_data, nonce, key),
        .XChaCha20Poly1305 => try algorithms.chacha.decryptPoly1305(out, tag, ciphertext, associated_data, nonce, key),
    }

    const block_size: usize = switch (method) {
        .Aes128Cbc, .Aes256Cbc => algorithms.aes_cbc.block_size,
        .Xtea => algorithms.xtea.block_size,
        else => 0,
    };

    if (block_size > 0) {
        if (out.len == 0) return error.InvalidPadding;
        const pad_len = out[out.len - 1];
        if (pad_len == 0 or pad_len > block_size or pad_len > out.len) return error.InvalidPadding;
        
        for (out[out.len - pad_len .. out.len]) |b| {
            if (b != pad_len) return error.InvalidPadding;
        }
        
        if (allocator.resize(out, out.len - pad_len)) {
            return out[0 .. out.len - pad_len];
        } else {
            const new_out = try allocator.dupe(u8, out[0 .. out.len - pad_len]);
            allocator.free(out);
            return new_out;
        }
    }

    return out;
}

test "encrypt/decrypt all methods" {
    const allocator = std.testing.allocator;
    const key_32 = "01234567890123456789012345678901"; // 32 bytes
    const key_16 = "0123456789012345"; // 16 bytes
    
    const msg = "Hello, cryptographic world!";
    const ad = "metadata";

    // Define test cases
    const TestCase = struct {
        method: Method,
        key: []const u8,
    };

    const cases = [_]TestCase{
        .{ .method = .Xor, .key = key_16 },
        .{ .method = .Aes128Gcm, .key = key_16 },
        .{ .method = .Aes256Gcm, .key = key_32 },
        .{ .method = .Aes128Cbc, .key = key_16 },
        .{ .method = .Aes256Cbc, .key = key_32 },
        .{ .method = .Xtea, .key = key_16 },
        .{ .method = .Salsa20, .key = key_32 },
        .{ .method = .ChaCha20, .key = key_32 },
        .{ .method = .XChaCha20, .key = key_32 },
        .{ .method = .XChaCha20Poly1305, .key = key_32 },
    };

    for (cases) |case| {
        // Encrypt
        const encrypted = try encrypt(allocator, case.method, case.key, msg, ad);
        defer allocator.free(encrypted);

        // Decrypt
        const decrypted = try decrypt(allocator, case.method, case.key, encrypted, ad);
        defer allocator.free(decrypted);

        // Verify
        try std.testing.expectEqualStrings(msg, decrypted);
    }
}

test "padding validation" {
    const allocator = std.testing.allocator;
    const key = "0123456789012345";
    
    const msg = "123456789012345"; // 15 bytes
    const encrypted = try encrypt(allocator, .Aes128Cbc, key, msg, "");
    defer allocator.free(encrypted);
    
    // Tamper with the last byte of ciphertext
    var bad_encrypted = try allocator.dupe(u8, encrypted);
    defer allocator.free(bad_encrypted);
    
    bad_encrypted[bad_encrypted.len - 1] ^= 0x01; 
    
    // Expect error
    try std.testing.expectError(error.InvalidPadding, decrypt(allocator, .Aes128Cbc, key, bad_encrypted, ""));
}

test "keySize values" {
    try std.testing.expectEqual(@as(usize, 0), keySize(.None));
    try std.testing.expectEqual(@as(usize, 16), keySize(.Xor));
    try std.testing.expectEqual(@as(usize, 16), keySize(.Aes128Gcm));
    try std.testing.expectEqual(@as(usize, 32), keySize(.Aes256Gcm));
    try std.testing.expectEqual(@as(usize, 32), keySize(.ChaCha20));
}

test "nonceSize values" {
    try std.testing.expectEqual(@as(usize, 0), nonceSize(.None));
    try std.testing.expectEqual(@as(usize, 0), nonceSize(.Xor));
    try std.testing.expectEqual(@as(usize, 12), nonceSize(.Aes128Gcm));
    try std.testing.expectEqual(@as(usize, 12), nonceSize(.ChaCha20));
    try std.testing.expectEqual(@as(usize, 24), nonceSize(.XChaCha20));
}

test "tagSize values" {
    try std.testing.expectEqual(@as(usize, 16), tagSize(.Aes128Gcm));
    try std.testing.expectEqual(@as(usize, 16), tagSize(.XChaCha20Poly1305));
    try std.testing.expectEqual(@as(usize, 0), tagSize(.Xor));
}

test "invalid key size error" {
    const allocator = std.testing.allocator;
    const key_bad = "123";
    try std.testing.expectError(error.InvalidKeySize, encrypt(allocator, .Aes128Gcm, key_bad, "msg", ""));
}
