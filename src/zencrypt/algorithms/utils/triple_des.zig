pub const des = @import("des.zig");

/// Triple DES Block processing (EDE)
/// Encrypt: E(k1) -> D(k2) -> E(k3)
/// Decrypt: D(k3) -> E(k2) -> D(k1)
pub fn processBlock3DES(block: u64, subkeys1: [16]u48, subkeys2: [16]u48, subkeys3: [16]u48, decrypting: bool) u64 {
    if (!decrypting) {
        // Encrypt: E1 -> D2 -> E3
        var b = des.processBlock(block, subkeys1, false);
        b = des.processBlock(b, subkeys2, true);
        b = des.processBlock(b, subkeys3, false);
        return b;
    } else {
        // Decrypt: D3 -> E2 -> D1
        var b = des.processBlock(block, subkeys3, true);
        b = des.processBlock(b, subkeys2, false);
        b = des.processBlock(b, subkeys1, true);
        return b;
    }
}
