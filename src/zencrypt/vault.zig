const std = @import("std");
const cipher = @import("cipher.zig");
const kdf = @import("kdf.zig");

const SALT_SIZE = 16; // Standard 128-bit salt

/// Encrypts data from `reader` to `writer` using a PASSWORD.
/// Output format: [SALT (16b)] [NONCE] [CIPHERTEXT] [TAG]
pub fn encryptWithPassword(
    allocator: std.mem.Allocator,
    method: cipher.Method,
    password: []const u8,
    kdf_config: kdf.Config,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    associated_data: []const u8,
) !void {
    // 1. Generate a random Salt
    var salt: [SALT_SIZE]u8 = undefined;
    std.crypto.random.bytes(&salt);

    // 2. Write the Salt to the output FIRST
    try writer.writeAll(&salt);

    // 3. Derive the encryption Key
    const key_len = cipher.keySize(method);
    const key = try allocator.alloc(u8, key_len);
    defer allocator.free(key);

    // Derive raw bytes using the salt
    try kdf.derive(allocator, key, password, &salt, kdf_config);

    // 4. Encrypt using your existing cipher logic
    try cipher.encrypt(allocator, method, key, reader, writer, associated_data);
}

/// Decrypts data from `reader` to `writer` using a PASSWORD.
pub fn decryptWithPassword(
    allocator: std.mem.Allocator,
    method: cipher.Method,
    password: []const u8,
    kdf_config: kdf.Config,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    associated_data: []const u8,
) !void {
    // 1. Read the Salt
    var salt: [SALT_SIZE]u8 = undefined;
    try reader.readSliceAll(&salt);

    // 2. Derive the same Key
    const key_len = cipher.keySize(method);
    const key = try allocator.alloc(u8, key_len);
    defer allocator.free(key);

    try kdf.derive(allocator, key, password, &salt, kdf_config);

    // 3. Decrypt
    try cipher.decrypt(allocator, method, key, reader, writer, associated_data);
}

test "Full Integration: Password Encrypt/Decrypt" {
    const allocator = std.testing.allocator;
    const pwd = "StrongPassword123!";
    const msg = "This is a secret message.";

    // Choose algorithm
    const method = cipher.Method.XChaCha20Poly1305;
    const config = kdf.Config.default_moderate;

    // --- ENCRYPT ---
    var enc_buf: std.Io.Writer.Allocating = .init(allocator);
    defer enc_buf.deinit();

    var plain_in: std.Io.Reader = .fixed(msg);
    try encryptWithPassword(allocator, method, pwd, config, &plain_in, &enc_buf.writer, "");

    const ciphertext = enc_buf.written();

    // --- DECRYPT ---
    var dec_buf: std.Io.Writer.Allocating = .init(allocator);
    defer dec_buf.deinit();

    var cipher_in: std.Io.Reader = .fixed(ciphertext);
    try decryptWithPassword(allocator, method, pwd, config, &cipher_in, &dec_buf.writer, "");

    try std.testing.expectEqualStrings(msg, dec_buf.written());
}
