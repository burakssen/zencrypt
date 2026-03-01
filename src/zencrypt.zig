const std = @import("std");
const Cipher = @import("cipher.zig").Cipher;

pub const Aes = Cipher(std.crypto.aead.aes_gcm.Aes256Gcm);
pub const XChaCha20 = Cipher(std.crypto.aead.chacha_poly.XChaCha20Poly1305);

pub const ZEncryptType = enum {
    aes,
    xchacha20,
};

pub const ZEncrypt = union(ZEncryptType) {
    aes: Aes,
    xchacha20: XChaCha20,

    pub fn init(allocator: std.mem.Allocator, T: ZEncryptType, password: []const u8) !ZEncrypt {
        return switch (T) {
            .aes => .{ .aes = try Aes.init(allocator, password) },
            .xchacha20 => .{ .xchacha20 = try XChaCha20.init(allocator, password) },
        };
    }

    pub fn encrypt(self: *ZEncrypt, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
        switch (self.*) {
            inline else => |*alg| try alg.encrypt(reader, writer),
        }
    }

    pub fn decrypt(self: *ZEncrypt, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
        switch (self.*) {
            inline else => |*alg| try alg.decrypt(reader, writer),
        }
    }

    pub fn deinit(self: *ZEncrypt) void {
        switch (self.*) {
            inline else => |*alg| alg.deinit(),
        }
    }
};

test "AES encryption/decryption" {
    const allocator = std.testing.allocator;
    var aes = try Aes.init(allocator, "testpassword");
    defer aes.deinit();
    const message = "Hello, ZEncrypt!";

    var in_stream: std.Io.Reader = .fixed(message);
    var out_buf: std.Io.Writer.Allocating = .init(allocator);
    defer out_buf.deinit();
    try aes.encrypt(&in_stream, &out_buf.writer);

    var encrypted_stream: std.Io.Reader = .fixed(out_buf.written());
    var decrypted_buf: std.Io.Writer.Allocating = .init(allocator);
    defer decrypted_buf.deinit();
    try aes.decrypt(&encrypted_stream, &decrypted_buf.writer);

    try std.testing.expectEqualStrings(message, decrypted_buf.written());
}

test "XChaCha20 encryption/decryption" {
    const allocator = std.testing.allocator;
    var xchacha = try XChaCha20.init(allocator, "testpassword");
    defer xchacha.deinit();
    const message = "Hello, XChaCha20!";

    var in_stream: std.Io.Reader = .fixed(message);
    var out_buf: std.Io.Writer.Allocating = .init(allocator);
    defer out_buf.deinit();
    try xchacha.encrypt(&in_stream, &out_buf.writer);

    var encrypted_stream: std.Io.Reader = .fixed(out_buf.written());
    var decrypted_buf: std.Io.Writer.Allocating = .init(allocator);
    defer decrypted_buf.deinit();
    try xchacha.decrypt(&encrypted_stream, &decrypted_buf.writer);

    try std.testing.expectEqualStrings(message, decrypted_buf.written());
}

test "ZEncrypt union dispatch" {
    const allocator = std.testing.allocator;
    const message = "Union test message";

    inline for (.{ ZEncryptType.aes, ZEncryptType.xchacha20 }) |T| {
        var zenc = try ZEncrypt.init(allocator, T, "testpassword");
        defer zenc.deinit();

        var out_buf: std.Io.Writer.Allocating = .init(allocator);
        defer out_buf.deinit();
        var in_stream: std.Io.Reader = .fixed(message);
        try zenc.encrypt(&in_stream, &out_buf.writer);

        var encrypted_stream: std.Io.Reader = .fixed(out_buf.written());
        var decrypted_buf: std.Io.Writer.Allocating = .init(allocator);
        defer decrypted_buf.deinit();
        try zenc.decrypt(&encrypted_stream, &decrypted_buf.writer);

        try std.testing.expectEqualStrings(message, decrypted_buf.written());
    }
}

test "decrypt-only initialization roundtrip" {
    const allocator = std.testing.allocator;
    const message = "decrypt-only init path";

    var encryptor = try ZEncrypt.init(allocator, .aes, "decrypt-only-password");
    defer encryptor.deinit();

    var encrypted_buf: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_buf.deinit();
    var in_stream: std.Io.Reader = .fixed(message);
    try encryptor.encrypt(&in_stream, &encrypted_buf.writer);

    var decryptor = try ZEncrypt.init(allocator, .aes, "decrypt-only-password");
    defer decryptor.deinit();

    var encrypted_stream: std.Io.Reader = .fixed(encrypted_buf.written());
    var decrypted_buf: std.Io.Writer.Allocating = .init(allocator);
    defer decrypted_buf.deinit();
    try decryptor.decrypt(&encrypted_stream, &decrypted_buf.writer);

    try std.testing.expectEqualStrings(message, decrypted_buf.written());
}

test "repeated encrypt calls generate unique salts" {
    const allocator = std.testing.allocator;
    const message = "salt uniqueness check";

    var encryptor = try ZEncrypt.init(allocator, .xchacha20, "salt-password");
    defer encryptor.deinit();

    var encrypted_a: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_a.deinit();
    var in_a: std.Io.Reader = .fixed(message);
    try encryptor.encrypt(&in_a, &encrypted_a.writer);

    var encrypted_b: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_b.deinit();
    var in_b: std.Io.Reader = .fixed(message);
    try encryptor.encrypt(&in_b, &encrypted_b.writer);

    const salt_a = encrypted_a.written()[0..32];
    const salt_b = encrypted_b.written()[0..32];
    try std.testing.expect(!std.mem.eql(u8, salt_a, salt_b));
}

test "tampered ciphertext is rejected" {
    const allocator = std.testing.allocator;
    const message = "tamper me";

    var zencrypt = try ZEncrypt.init(allocator, .aes, "tamper-password");
    defer zencrypt.deinit();

    var encrypted_buf: std.Io.Writer.Allocating = .init(allocator);
    defer encrypted_buf.deinit();
    var in_stream: std.Io.Reader = .fixed(message);
    try zencrypt.encrypt(&in_stream, &encrypted_buf.writer);

    var tampered = try allocator.dupe(u8, encrypted_buf.written());
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    var tampered_stream: std.Io.Reader = .fixed(tampered);
    var out_buf: std.Io.Writer.Allocating = .init(allocator);
    defer out_buf.deinit();

    zencrypt.decrypt(&tampered_stream, &out_buf.writer) catch {
        return;
    };

    return error.ExpectedTamperFailure;
}

test "legacy-format fixture decrypts" {
    const allocator = std.testing.allocator;
    const fixture_password = "fixture-password";
    const fixture_plaintext = "legacy fixture message";
    const fixture_ciphertext = [_]u8{
        0xb0, 0x9e, 0xad, 0x9d, 0xf5, 0xdc, 0xfe, 0x55,
        0xf6, 0xc0, 0x9d, 0xdd, 0xec, 0x8a, 0x54, 0x9c,
        0x10, 0xf6, 0x78, 0xa6, 0xbc, 0x3d, 0xc1, 0xf5,
        0x28, 0x17, 0x76, 0x8f, 0x15, 0x83, 0x14, 0xd3,
        0x16, 0x00, 0x00, 0x00, 0x55, 0x1b, 0x3f, 0x94,
        0x88, 0xf5, 0x29, 0x3e, 0x98, 0xa3, 0x15, 0x73,
        0xb1, 0xbe, 0x8b, 0xea, 0x06, 0x36, 0x7d, 0x3a,
        0xab, 0xb9, 0x41, 0x03, 0x13, 0xdf, 0x43, 0x8a,
        0xf4, 0xfd, 0x51, 0x47, 0x87, 0x29, 0x81, 0x8e,
        0xe8, 0xf0, 0x43, 0xce, 0x70, 0x4d, 0xe0, 0x3f,
        0xbf, 0x33, 0xda, 0x3f, 0x43, 0x31,
    };

    var decryptor = try ZEncrypt.init(allocator, .aes, fixture_password);
    defer decryptor.deinit();

    var in_stream: std.Io.Reader = .fixed(&fixture_ciphertext);
    var out_buf: std.Io.Writer.Allocating = .init(allocator);
    defer out_buf.deinit();
    try decryptor.decrypt(&in_stream, &out_buf.writer);

    try std.testing.expectEqualStrings(fixture_plaintext, out_buf.written());
}
