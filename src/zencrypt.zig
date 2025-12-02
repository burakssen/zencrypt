const std = @import("std");

pub const password = @import("zencrypt/password.zig");
pub const cipher = @import("zencrypt/cipher.zig");
pub const kdf = @import("zencrypt/kdf.zig");
pub const vault = @import("zencrypt/vault.zig");

test {
    _ = password;
    _ = cipher;
    _ = kdf;
    _ = vault;
    _ = @import("zencrypt/algorithms/xor.zig");
    _ = @import("zencrypt/algorithms/xtea.zig");
    _ = @import("zencrypt/algorithms/aes_cbc.zig");
    _ = @import("zencrypt/algorithms/aes_gcm.zig");
    _ = @import("zencrypt/algorithms/salsa.zig");
    _ = @import("zencrypt/algorithms/chacha.zig");
}
