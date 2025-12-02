const std = @import("std");
const ze = @import("zencrypt");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Zencrypt Library Demonstration\n", .{});
    std.debug.print("==============================\n\n", .{});

    // --- Password Hashing ---
    try demoPassword(allocator);

    // --- Symmetric Encryption ---
    const message = "This is a secret message verified by Zencrypt!";
    const ad = "header-data";

    // 16-byte keys
    const key16 = "0123456789abcdef"; 
    // 32-byte keys
    const key32 = "0123456789abcdef0123456789abcdef";

    // Simple/Lightweight
    try demoCipher(allocator, .Xor, key16, message, ad);
    try demoCipher(allocator, .Xtea, key16, message, ad);
    
    // AES Family
    try demoCipher(allocator, .Aes128Cbc, key16, message, ad);
    try demoCipher(allocator, .Aes256Cbc, key32, message, ad);
    try demoCipher(allocator, .Aes128Gcm, key16, message, ad);
    try demoCipher(allocator, .Aes256Gcm, key32, message, ad);

    // Stream Ciphers
    try demoCipher(allocator, .Salsa20, key32, message, ad);
    try demoCipher(allocator, .ChaCha20, key32, message, ad);
    try demoCipher(allocator, .XChaCha20, key32, message, ad);
    
    // Modern AEAD
    try demoCipher(allocator, .XChaCha20Poly1305, key32, message, ad);
}

fn demoPassword(allocator: std.mem.Allocator) !void {
    std.debug.print("--- Password Hashing (Argon2) ---\n", .{});
    const password = "CorrectHorseBatteryStaple";
    std.debug.print("Password:  {s}\n", .{password});

    const hash = try ze.password.hash(allocator, password, .default);
    defer allocator.free(hash);
    std.debug.print("Hash:      {s}\n", .{hash});

    try ze.password.verify(allocator, password, hash);
    std.debug.print("Verify:    OK\n\n", .{});
}

fn demoCipher(
    allocator: std.mem.Allocator, 
    method: ze.cipher.Method, 
    key: []const u8, 
    message: []const u8,
    ad: []const u8
) !void {
    std.debug.print("--- {s} ---\n", .{@tagName(method)});
    
    // Encrypt
    const encrypted = try ze.cipher.encrypt(allocator, method, key, message, ad);
    defer allocator.free(encrypted);

    std.debug.print("Message:   {s}\n", .{message});
    // Print key preview just to show it's being used
    if (key.len > 8) {
        std.debug.print("Key:       {s}...\n", .{key[0..8]});
    } else {
        std.debug.print("Key:       {s}\n", .{key});
    }
    
    // Print hex preview of ciphertext (first 32 bytes or all if shorter)
    const preview_len = @min(encrypted.len, 32);
    std.debug.print("Encrypted: ", .{});
    for (encrypted[0..preview_len]) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    if (encrypted.len > preview_len) {
        std.debug.print("... ({d} bytes total)", .{encrypted.len});
    }
    std.debug.print("\n", .{});

    // Decrypt
    const decrypted = try ze.cipher.decrypt(allocator, method, key, encrypted, ad);
    defer allocator.free(decrypted);

    std.debug.print("Decrypted: {s}\n", .{decrypted});
    
    if (!std.mem.eql(u8, message, decrypted)) {
        std.debug.print("Result:    FAILED (Mismatch)\n\n", .{});
        return error.DemoFailed;
    }
    std.debug.print("Result:    OK\n\n", .{});
}