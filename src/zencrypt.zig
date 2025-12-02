const std = @import("std");

pub const password = @import("zencrypt/password.zig");
pub const cipher = @import("zencrypt/cipher.zig");

test {
    _ = password;
    _ = cipher;
    _ = @import("zencrypt/algorithms/xor.zig");
    _ = @import("zencrypt/algorithms/xtea.zig");
    _ = @import("zencrypt/algorithms/aes_cbc.zig");
    _ = @import("zencrypt/algorithms/aes_gcm.zig");
    _ = @import("zencrypt/algorithms/salsa.zig");
    _ = @import("zencrypt/algorithms/chacha.zig");
}