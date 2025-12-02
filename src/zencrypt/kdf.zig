const std = @import("std");

pub const Algorithm = enum {
    Argon2,
    Scrypt,
    Pbkdf2,
};

pub const Config = union(Algorithm) {
    Argon2: std.crypto.pwhash.argon2.Params,
    Scrypt: std.crypto.pwhash.scrypt.Params,
    Pbkdf2: struct { rounds: u32 = 100_000 },

    /// Strong security (high memory). Use for file encryption on desktop.
    pub const default_strong: Config = .{
        .Argon2 = .{ .m = 65536, .t = 3, .p = 4 },
    };

    /// Moderate security. Faster, less memory.
    pub const default_moderate: Config = .{
        .Argon2 = .{ .m = 8192, .t = 3, .p = 1 },
    };
};

/// Derives a raw key (bytes) from a password and salt.
/// out_key.len determines the size (e.g., 32 for AES-256).
pub fn derive(
    allocator: std.mem.Allocator,
    out_key: []u8,
    secret: []const u8,
    salt: []const u8,
    config: Config,
) !void {
    switch (config) {
        .Argon2 => |params| {
            try std.crypto.pwhash.argon2.kdf(
                allocator,
                out_key,
                secret,
                salt,
                params,
                .argon2i,
            );
        },
        .Scrypt => |params| {
            try std.crypto.pwhash.scrypt.kdf(
                allocator,
                out_key,
                secret,
                salt,
                params,
            );
        },
        .Pbkdf2 => |params| {
            try std.crypto.pwhash.pbkdf2(
                out_key,
                secret,
                salt,
                params.rounds,
                std.crypto.auth.hmac.sha2.HmacSha256,
            );
        },
    }
}
