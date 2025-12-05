const std = @import("std");

// XTEA Constants
pub const DELTA: u32 = 0x9E3779B9;
pub const NUM_ROUNDS: u32 = 32; // 32 cycles = 64 rounds

/// Helper to ensure wrapping left shift without panic in Debug modes
fn shl(val: u32, shift: u5) u32 {
    return @as(u32, @truncate(@as(u64, val) << shift));
}

/// Helper: Parse 16-byte key into 4 u32 words (Big Endian)
pub fn keyToWords(key: []const u8) ![4]u32 {
    if (key.len != 16) return error.InvalidKeyLength;
    var k: [4]u32 = undefined;
    for (0..4) |i| {
        k[i] = std.mem.readInt(u32, key[i * 4 ..][0..4], .big);
    }
    return k;
}

pub fn encipher(block: u64, key: [4]u32) u64 {
    var v0: u32 = @intCast(block >> 32);
    var v1: u32 = @intCast(block & 0xFFFFFFFF);
    var sum: u32 = 0;

    for (0..NUM_ROUNDS) |_| {
        // v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3])
        const term1 = (shl(v1, 4) ^ (v1 >> 5)) +% v1;
        const term2 = sum +% key[sum & 3];
        v0 +%= term1 ^ term2;

        sum +%= DELTA;

        // v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[sum >> 11 & 3])
        const term3 = (shl(v0, 4) ^ (v0 >> 5)) +% v0;
        const term4 = sum +% key[(sum >> 11) & 3];
        v1 +%= term3 ^ term4;
    }

    return (@as(u64, v0) << 32) | @as(u64, v1);
}

pub fn decipher(block: u64, key: [4]u32) u64 {
    var v0: u32 = @intCast(block >> 32);
    var v1: u32 = @intCast(block & 0xFFFFFFFF);
    var sum: u32 = DELTA *% NUM_ROUNDS;

    for (0..NUM_ROUNDS) |_| {
        // v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + key[sum >> 11 & 3])
        const term1 = (shl(v0, 4) ^ (v0 >> 5)) +% v0;
        const term2 = sum +% key[(sum >> 11) & 3];
        v1 -%= term1 ^ term2;

        sum -%= DELTA;

        // v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + key[sum & 3])
        const term3 = (shl(v1, 4) ^ (v1 >> 5)) +% v1;
        const term4 = sum +% key[sum & 3];
        v0 -%= term3 ^ term4;
    }

    return (@as(u64, v0) << 32) | @as(u64, v1);
}
