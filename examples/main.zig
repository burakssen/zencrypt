const std = @import("std");
const ze = @import("zencrypt"); // Assumes your library is exposed as 'zencrypt'

pub fn main() !void {
    // 1. Setup Memory Allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== Zencrypt Full Demo ===\n", .{});

    // --- Scenario A: User Passwords ---
    try demoPassword(allocator);

    // --- Scenario B: InMemory String Encryption ---
    try demoStringEncryption(allocator);

    // --- Scenario C: File Encryption ---
    // We will create a dummy file, encrypt it, then decrypt it.
    try demoFileEncryption(allocator);
}

/// Scenario A: Hashing and Verifying Passwords
fn demoPassword(allocator: std.mem.Allocator) !void {
    std.debug.print("\n[A] Password Hashing (Argon2)\n", .{});

    const plain_password = "correct-horse-battery-staple";

    // 1. Hash
    // The library handles salt generation automatically.
    const hash = try ze.password.hash(allocator, plain_password, .default);
    defer allocator.free(hash);
    std.debug.print("   > Hashed: {s}\n", .{hash});

    // 2. Verify
    // Takes the plain text and the stored hash string.
    try ze.password.verify(allocator, plain_password, hash);
    std.debug.print("   > Verification: SUCCESS\n", .{});
}

/// Scenario B: Encrypting Strings in Memory
fn demoStringEncryption(allocator: std.mem.Allocator) !void {
    std.debug.print("\n[B] String Encryption (XChaCha20-Poly1305)\n", .{});

    const key = "0123456789abcdef0123456789abcdef"; // 32 bytes
    const message = "The quick brown fox jumps over the lazy dog";
    const aad = "header-v1"; // Optional Associated Data

    // --- Encrypt ---
    var ciphertext_buffer: std.Io.Writer.Allocating = .init(allocator);
    defer ciphertext_buffer.deinit();

    // Create a stream reader from the const string
    var msg_stream: std.Io.Reader = .fixed(message);

    try ze.cipher.encrypt(allocator, .XChaCha20Poly1305, key, &msg_stream, &ciphertext_buffer.writer, aad);

    const ciphertext = ciphertext_buffer.written();

    std.debug.print("   > Encrypted Size: {d} bytes (Nonce + Msg + Tag)\n", .{ciphertext.len});

    // --- Decrypt ---
    var plaintext_buffer: std.Io.Writer.Allocating = .init(allocator);
    defer plaintext_buffer.deinit();

    // Create a stream reader from the encrypted byte array
    var cipher_stream: std.Io.Reader = .fixed(ciphertext);

    try ze.cipher.decrypt(allocator, .XChaCha20Poly1305, key, &cipher_stream, &plaintext_buffer.writer, aad);

    const plaintext = plaintext_buffer.written();

    std.debug.print("   > Decrypted: {s}\n", .{plaintext});
}

/// Scenario C: Encrypting Files on Disk
fn demoFileEncryption(allocator: std.mem.Allocator) !void {
    std.debug.print("\n[C] File Encryption (AES-256-GCM)\n", .{});

    const key = "0123456789abcdef0123456789abcdef"; // 32 bytes
    const cwd = std.fs.cwd();

    // 1. Create a dummy file to encrypt
    const secret_content = "This is confidential file data stored on disk.";
    try cwd.writeFile(.{ .sub_path = "secret.txt", .data = secret_content });
    std.debug.print("   > Created 'secret.txt'\n", .{});

    // 2. Encrypt: secret.txt -> secret.enc
    {
        var in_file = try cwd.openFile("secret.txt", .{});
        defer in_file.close();

        var in_file_buffer: [1024]u8 = undefined;
        var in_file_reader = in_file.reader(&in_file_buffer);
        const reader = &in_file_reader.interface;

        var out_file = try cwd.createFile("secret.enc", .{});
        defer out_file.close();

        var out_file_buffer: [1024]u8 = undefined;
        var out_file_writer = out_file.writer(&out_file_buffer);
        const writer = &out_file_writer.interface;

        try ze.cipher.encrypt(allocator, .Aes256Gcm, // Using AES for this example
            key, reader, writer, "" // No AAD
        );
        std.debug.print("   > Encrypted to 'secret.enc'\n", .{});

        try writer.flush();
    }

    // 3. Decrypt: secret.enc -> secret.dec
    {
        var in_file = try cwd.openFile("secret.enc", .{});
        defer in_file.close();

        var in_file_buffer: [1024]u8 = undefined;
        var in_file_reader = in_file.reader(&in_file_buffer);
        const reader = &in_file_reader.interface;

        var out_file = try cwd.createFile("secret.dec", .{});
        defer out_file.close();

        var out_file_buffer: [1024]u8 = undefined;
        var out_file_writer = out_file.writer(&out_file_buffer);
        const writer = &out_file_writer.interface;

        try ze.cipher.decrypt(allocator, .Aes256Gcm, key, reader, writer, "");
        std.debug.print("   > Decrypted to 'secret.dec'\n", .{});

        try writer.flush();
    }

    // 4. Verification check
    const check = try cwd.readFileAlloc(allocator, "secret.dec", 1024);
    defer allocator.free(check);

    if (std.mem.eql(u8, check, secret_content)) {
        std.debug.print("   > File Integrity Check: PASSED\n", .{});
    } else {
        std.debug.print("   > File Integrity Check: FAILED\n", .{});
    }

    // Cleanup files
    try cwd.deleteFile("secret.txt");
    try cwd.deleteFile("secret.enc");
    try cwd.deleteFile("secret.dec");
}
