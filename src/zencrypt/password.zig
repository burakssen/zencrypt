const std = @import("std");

pub const Algorithm = enum {
    Argon2,
    Scrypt,
    Bcrypt,
};

pub const Config = union(Algorithm) {
    Argon2: std.crypto.pwhash.argon2.Params,
    Scrypt: std.crypto.pwhash.scrypt.Params,
    Bcrypt: std.crypto.pwhash.bcrypt.Params,

    pub const default: Config = .{
        .Argon2 = .{
            .m = 65536,
            .t = 3,
            .p = 4,
        },
    };
};

pub fn hash(
    allocator: std.mem.Allocator,
    password: []const u8,
    config: Config,
) ![]u8 {
    switch (config) {
        .Argon2 => |params| {
            const out = try allocator.alloc(u8, 256);
            errdefer allocator.free(out);

            const options = std.crypto.pwhash.argon2.HashOptions{
                .allocator = allocator,
                .params = params,
                .encoding = .phc,
                .mode = .argon2id,
            };

            const slice = try std.crypto.pwhash.argon2.strHash(password, options, out);
            // Shrink to fit actual hash length
            if (allocator.resize(out, slice.len)) {
                return out[0..slice.len];
            } else {
                const new_out = try allocator.realloc(out, slice.len);
                return new_out;
            }
        },
        .Scrypt => |params| {
            const out = try allocator.alloc(u8, 256);
            errdefer allocator.free(out);

            const options = std.crypto.pwhash.scrypt.HashOptions{
                .allocator = allocator,
                .params = params,
                .encoding = .phc,
            };

            const slice = try std.crypto.pwhash.scrypt.strHash(password, options, out);
            if (allocator.resize(out, slice.len)) {
                return out[0..slice.len];
            } else {
                const new_out = try allocator.realloc(out, slice.len);
                return new_out;
            }
        },
        .Bcrypt => |params| {
            const out = try allocator.alloc(u8, 128);
            errdefer allocator.free(out);

            const options = std.crypto.pwhash.bcrypt.HashOptions{
                .params = params,
                .encoding = .phc,
            };

            const slice = try std.crypto.pwhash.bcrypt.strHash(password, options, out);
            // Bcrypt hash len is fixed, but strHash returns a slice, so we return the allocated buffer
            // We should probably just return out[0..slice.len] but let's be consistent with realloc
            if (out.len != slice.len) {
                 if (allocator.resize(out, slice.len)) {
                    return out[0..slice.len];
                } else {
                    const new_out = try allocator.realloc(out, slice.len);
                    return new_out;
                }
            }
            return out;
        },
    }
}

pub fn verify(
    allocator: std.mem.Allocator,
    password: []const u8,
    hash_str: []const u8,
) !void {
    if (std.mem.startsWith(u8, hash_str, "$argon2")) {
        return std.crypto.pwhash.argon2.strVerify(hash_str, password, .{ .allocator = allocator });
    } else if (std.mem.startsWith(u8, hash_str, "$scrypt")) {
        return std.crypto.pwhash.scrypt.strVerify(hash_str, password, .{ .allocator = allocator });
    } else if (std.mem.startsWith(u8, hash_str, "$2") or std.mem.startsWith(u8, hash_str, "$bcrypt")) {
        // Bcrypt strVerify in Zig std might not take options or might take empty struct
        return std.crypto.pwhash.bcrypt.strVerify(hash_str, password, .{ .silently_truncate_password = true });
    } else {
        return error.UnknownHashFormat;
    }
}

test "argon2 hash and verify" {
    const allocator = std.testing.allocator;
    const pwd = "password123";
    
    // Minimal params for speed in tests
    const params = std.crypto.pwhash.argon2.Params{
        .m = 8,
        .t = 1,
        .p = 1,
    };
    
    const h = try hash(allocator, pwd, .{ .Argon2 = params });
    defer allocator.free(h);
    
    try verify(allocator, pwd, h);
    try std.testing.expectError(error.PasswordVerificationFailed, verify(allocator, "wrong", h));
}

test "scrypt hash and verify" {
    const allocator = std.testing.allocator;
    const pwd = "password123";
    
    // Minimal params
    const params = std.crypto.pwhash.scrypt.Params{
        .ln = 4, // N=16
        .r = 1,
        .p = 1,
    };
    
    const h = try hash(allocator, pwd, .{ .Scrypt = params });
    defer allocator.free(h);
    
    try verify(allocator, pwd, h);
    try std.testing.expectError(error.PasswordVerificationFailed, verify(allocator, "wrong", h));
}

test "bcrypt hash and verify" {
    const allocator = std.testing.allocator;
    const pwd = "password123";
    
    const params = std.crypto.pwhash.bcrypt.Params{
        .rounds_log = 4, // Minimum cost
        .silently_truncate_password = true,
    };
    
    const h = try hash(allocator, pwd, .{ .Bcrypt = params });
    defer allocator.free(h);
    
    try verify(allocator, pwd, h);
    try std.testing.expectError(error.PasswordVerificationFailed, verify(allocator, "wrong", h));
}