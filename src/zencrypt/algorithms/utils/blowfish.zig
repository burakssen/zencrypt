// utils/blowfish.zig - Blowfish algorithm core
const std = @import("std");

// Import initial P-array and S-boxes (truncated here for brevity - see full data below)
const constants = @import("constants/blowfish.zig");
const P_INIT = constants.P_INIT;
const S_INIT = constants.S_INIT;

pub const BlowfishContext = struct {
    p: [18]u32,
    s: [4][256]u32,

    pub fn init(key: []const u8) !BlowfishContext {
        var ctx = BlowfishContext{
            .p = P_INIT,
            .s = S_INIT,
        };

        // XOR P-array with key
        var key_idx: usize = 0;
        for (0..18) |i| {
            var data: u32 = 0;
            for (0..4) |_| {
                data = (data << 8) | @as(u32, key[key_idx]);
                key_idx = (key_idx + 1) % key.len;
            }
            ctx.p[i] ^= data;
        }

        // Encrypt all-zero blocks to initialize P and S
        var l: u32 = 0;
        var r: u32 = 0;

        // Initialize P-array
        for (0..9) |i| {
            ctx.encryptBlockInPlace(&l, &r);
            ctx.p[i * 2] = l;
            ctx.p[i * 2 + 1] = r;
        }

        // Initialize S-boxes
        for (0..4) |i| {
            for (0..128) |j| {
                ctx.encryptBlockInPlace(&l, &r);
                ctx.s[i][j * 2] = l;
                ctx.s[i][j * 2 + 1] = r;
            }
        }

        return ctx;
    }

    fn f(self: *const BlowfishContext, x: u32) u32 {
        const a = (x >> 24) & 0xFF;
        const b = (x >> 16) & 0xFF;
        const c = (x >> 8) & 0xFF;
        const d = x & 0xFF;

        const y = (self.s[0][a] +% self.s[1][b]) ^ self.s[2][c];
        return y +% self.s[3][d];
    }

    fn encryptBlockInPlace(self: *const BlowfishContext, l: *u32, r: *u32) void {
        var left = l.*;
        var right = r.*;

        for (0..16) |i| {
            left ^= self.p[i];
            right ^= self.f(left);
            std.mem.swap(u32, &left, &right);
        }
        std.mem.swap(u32, &left, &right);

        right ^= self.p[16];
        left ^= self.p[17];

        l.* = left;
        r.* = right;
    }

    pub fn encryptBlock(self: *const BlowfishContext, block: u64) u64 {
        var l: u32 = @intCast(block >> 32);
        var r: u32 = @intCast(block & 0xFFFFFFFF);

        self.encryptBlockInPlace(&l, &r);

        return (@as(u64, l) << 32) | @as(u64, r);
    }

    pub fn decryptBlock(self: *const BlowfishContext, block: u64) u64 {
        const l: u32 = @intCast(block >> 32);
        const r: u32 = @intCast(block & 0xFFFFFFFF);

        var left = l;
        var right = r;

        for (0..16) |i| {
            left ^= self.p[17 - i];
            right ^= self.f(left);
            std.mem.swap(u32, &left, &right);
        }
        std.mem.swap(u32, &left, &right);

        right ^= self.p[1];
        left ^= self.p[0];

        return (@as(u64, left) << 32) | @as(u64, right);
    }
};

pub fn bytesToBlock(bytes: *const [8]u8) u64 {
    var block: u64 = 0;
    for (bytes, 0..) |byte, i| {
        block |= @as(u64, byte) << @intCast(56 - i * 8);
    }
    return block;
}

pub fn blockToBytes(block: u64) [8]u8 {
    var bytes: [8]u8 = undefined;
    for (0..8) |i| {
        bytes[i] = @intCast((block >> @intCast(56 - i * 8)) & 0xFF);
    }
    return bytes;
}

pub fn writeBlock(writer: anytype, block: u64) !void {
    for (0..8) |i| {
        const byte: u8 = @intCast((block >> @intCast(56 - i * 8)) & 0xFF);
        try writer.writeByte(byte);
    }
}
