const constants = @import("constants/des.zig");

pub fn permute(input: u64, table: []const u8, out_bits: u8) u64 {
    var output: u64 = 0;
    for (table, 0..) |pos, i| {
        const bit = (input >> @intCast(64 - pos)) & 1;
        output |= bit << @intCast(out_bits - 1 - i);
    }
    return output;
}

pub fn leftRotate28(val: u32, shift: u5) u32 {
    return ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;
}

pub fn generateSubkeys(key: u64) [16]u48 {
    var subkeys: [16]u48 = undefined;

    const permuted_key = permute(key, &constants.PC1, 56);
    var c: u32 = @intCast((permuted_key >> 28) & 0x0FFFFFFF);
    var d: u32 = @intCast(permuted_key & 0x0FFFFFFF);

    for (0..16) |i| {
        c = leftRotate28(c, constants.SHIFTS[i]);
        d = leftRotate28(d, constants.SHIFTS[i]);

        const cd: u64 = (@as(u64, c) << 28) | @as(u64, d);
        subkeys[i] = @intCast(permute(cd, &constants.PC2, 48));
    }

    return subkeys;
}

pub fn feistel(right: u32, subkey: u48) u32 {
    const expanded = permute(@as(u64, right) << 32, &constants.E, 48);

    const xored = expanded ^ subkey;

    var sbox_out: u32 = 0;
    for (0..8) |i| {
        const block = @as(u8, @intCast((xored >> @intCast(42 - i * 6)) & 0x3F));
        const row = ((block & 0x20) >> 4) | (block & 0x01);
        const col = (block >> 1) & 0x0F;
        const val = constants.S[i][row][col];
        sbox_out |= @as(u32, val) << @intCast(28 - i * 4);
    }

    return @intCast(permute(@as(u64, sbox_out) << 32, &constants.P, 32));
}

pub fn processBlock(block: u64, subkeys: [16]u48, dec: bool) u64 {
    const permuted = permute(block, &constants.IP, 64);

    var left: u32 = @intCast(permuted >> 32);
    var right: u32 = @intCast(permuted & 0xFFFFFFFF);

    for (0..16) |i| {
        const round = if (dec) 15 - i else i;
        const temp = right;
        right = left ^ feistel(right, subkeys[round]);
        left = temp;
    }

    const combined: u64 = (@as(u64, right) << 32) | @as(u64, left);
    return permute(combined, &constants.FP, 64);
}

pub fn keyToU64(key: []const u8) !u64 {
    if (key.len != 8) return error.InvalidKeyLength;
    var result: u64 = 0;
    for (key, 0..) |byte, i| {
        result |= @as(u64, byte) << @intCast(56 - i * 8);
    }
    return result;
}
