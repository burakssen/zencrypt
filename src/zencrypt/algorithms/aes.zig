const std = @import("std");
const common = @import("common.zig");
const Aes = @This();

pub const AesType = enum {
    Aes128,
    Aes256,
};

allocator: std.mem.Allocator,
aes_type: AesType,

pub fn init(allocator: std.mem.Allocator, aes_type: AesType) Aes {
    return Aes{
        .allocator = allocator,
        .aes_type = aes_type,
    };
}

const Core = common.BlockCipher(16);

pub fn encrypt(self: *Aes, reader: anytype, writer: anytype, key: []const u8) !void {
    switch (self.aes_type) {
        .Aes128 => {
            const Ctx = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128);
            try Core.encrypt(reader, writer, Ctx.init(key[0..16].*), encryptBlock(Ctx));
        },
        .Aes256 => {
            const Ctx = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256);
            try Core.encrypt(reader, writer, Ctx.init(key[0..32].*), encryptBlock(Ctx));
        },
    }
}

pub fn decrypt(self: *Aes, reader: anytype, writer: anytype, key: []const u8) !void {
    switch (self.aes_type) {
        .Aes128 => {
            const Ctx = std.crypto.core.aes.AesDecryptCtx(std.crypto.core.aes.Aes128);
            try Core.decrypt(reader, writer, Ctx.init(key[0..16].*), decryptBlock(Ctx));
        },
        .Aes256 => {
             const Ctx = std.crypto.core.aes.AesDecryptCtx(std.crypto.core.aes.Aes256);
            try Core.decrypt(reader, writer, Ctx.init(key[0..32].*), decryptBlock(Ctx));
        },
    }
}

fn encryptBlock(comptime Context: type) fn (Context, *[16]u8) void {
    return struct {
        fn func(ctx: Context, block: *[16]u8) void {
            var out: [16]u8 = undefined;
            ctx.encrypt(&out, block);
            block.* = out;
        }
    }.func;
}

fn decryptBlock(comptime Context: type) fn (Context, *[16]u8) void {
    return struct {
        fn func(ctx: Context, block: *[16]u8) void {
            var out: [16]u8 = undefined;
            ctx.decrypt(&out, block);
            block.* = out;
        }
    }.func;
}
