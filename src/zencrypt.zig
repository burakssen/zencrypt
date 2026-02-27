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
