const std = @import("std");
const algorithms = @import("algorithms/algorithms.zig"); // Assuming xor.zig is in the same directory, adjust path if needed

pub const CryptorType = enum {
    None,
    Xor,
    Des,
    TripleDes,
    Idea,
    Aes,
    AesGcm,
    Xtea,
    Blowfish,
    Rsa,
    Salsa20,
    ChaCha20,
    XChaCha20,
    XChaCha20Poly1305,
};

pub const KdfOptions = struct {
    iterations: u32,
    salt_length: usize,

    pub const default = KdfOptions{
        .iterations = 100_000,
        .salt_length = 16,
    };
};

pub const DerivedKey = struct {
    key: []u8,
    salt: []const u8,
};

pub const Impl = union(CryptorType) {
    None: void,
    Xor: algorithms.Xor,
    Des: algorithms.Des,
    TripleDes: void,
    Idea: void,
    Aes: void,
    AesGcm: void,
    Xtea: void,
    Blowfish: void,
    Rsa: void,
    Salsa20: void,
    ChaCha20: void,
    XChaCha20: void,
    XChaCha20Poly1305: void,
};

const Cryptor = @This();

allocator: std.mem.Allocator,
impl: Impl,
kdf_options: KdfOptions = .default,

pub fn init(allocator: std.mem.Allocator, cryptor_type: CryptorType) !Cryptor {
    const impl = switch (cryptor_type) {
        .None => .None,
        .Xor => Cryptor.Impl{ .Xor = algorithms.Xor.init(allocator) },
        .Des => Cryptor.Impl{ .Des = algorithms.Des{} },
        .TripleDes => .TripleDes,
        .Idea => .Idea,
        .Aes => .Aes,
        .AesGcm => .AesGcm,
        .Xtea => .Xtea,
        .Blowfish => .Blowfish,
        .Rsa => .Rsa,
        .Salsa20 => .Salsa20,
        .ChaCha20 => .ChaCha20,
        .XChaCha20 => .XChaCha20,
        .XChaCha20Poly1305 => .XChaCha20Poly1305,
    };

    return Cryptor{
        .allocator = allocator,
        .impl = impl,
    };
}

pub fn encrypt(self: *Cryptor, reader: *std.Io.Reader, writer: *std.Io.Writer, password: []const u8) !void {
    // 1. Handle .None immediately (No key derivation, no salt write)
    if (self.impl == .None) {
        _ = try reader.stream(writer, .unlimited);
        return;
    }

    // 2. Logic for algorithms that require a key
    // Derive key (generates a new random salt since we pass null)
    const derived_key = try self.deriveKey(password, null);
    defer {
        self.allocator.free(derived_key.key);
        self.allocator.free(derived_key.salt);
    }

    // Write the generated salt to the output stream first
    try writer.writeAll(derived_key.salt);

    // 3. Perform Encryption
    switch (self.impl) {
        .None => unreachable, // Handled above
        .Xor => |*xor| return xor.encrypt(reader, writer, derived_key.key),
        .Des => |*des| return des.encrypt(reader, writer, derived_key.key),
        .TripleDes, .Idea, .Aes, .AesGcm, .Xtea, .Blowfish, .Rsa, .Salsa20, .ChaCha20, .XChaCha20, .XChaCha20Poly1305 => return error.NotImplemented,
    }
}

pub fn decrypt(self: *Cryptor, reader: *std.Io.Reader, writer: *std.Io.Writer, password: []const u8) !void {
    // 1. Handle .None immediately (No salt read, no key derivation)
    if (self.impl == .None) {
        _ = try reader.stream(writer, .unlimited);
        return;
    }

    // 2. Logic for algorithms that require a key
    const options = self.kdf_options;

    // Read the salt from the input stream
    const salt_buffer = try reader.readAlloc(self.allocator, options.salt_length);
    defer self.allocator.free(salt_buffer); // Free the buffer read from stream

    if (salt_buffer.len != options.salt_length) {
        return error.InvalidSaltLength;
    }

    // Derive the key
    const derived_key = try self.deriveKey(password, salt_buffer);
    defer {
        self.allocator.free(derived_key.key);
        self.allocator.free(derived_key.salt);
    }

    // 3. Perform Decryption
    switch (self.impl) {
        .None => unreachable, // Handled above
        .Xor => |*xor| return xor.decrypt(reader, writer, derived_key.key),
        .Des => |*des| return des.decrypt(reader, writer, derived_key.key),
        .TripleDes, .Idea, .Aes, .AesGcm, .Xtea, .Blowfish, .Rsa, .Salsa20, .ChaCha20, .XChaCha20, .XChaCha20Poly1305 => return error.NotImplemented,
    }
}

fn getKeyLength(self: Cryptor) usize {
    return switch (self.impl) {
        .None => 0,
        .Xor => 16,
        .Des => 8,
        .TripleDes => 24,
        .Idea => 16,
        .Aes => 32,
        .AesGcm => 32,
        .Xtea => 16,
        .Blowfish => 32,
        .Rsa => 256,
        .Salsa20 => 32,
        .ChaCha20 => 32,
        .XChaCha20 => 32,
        .XChaCha20Poly1305 => 32,
    };
}

fn deriveKey(self: *Cryptor, password: []const u8, salt: ?[]const u8) !DerivedKey {
    const options = self.kdf_options;
    // Use the allocator stored in the main struct
    const allocator = self.allocator;

    const salt_slice = try allocator.alloc(u8, options.salt_length);
    defer allocator.free(salt_slice);

    if (salt) |provided_salt| {
        if (provided_salt.len != options.salt_length) {
            return error.InvalidSaltLength;
        }
        @memcpy(salt_slice, provided_salt);
    } else {
        std.crypto.random.bytes(salt_slice);
    }

    const key_length = self.getKeyLength();
    // If key length is 0 (None), handle gracefully
    if (key_length == 0) {
        const empty_key = try allocator.alloc(u8, 0);
        const salt_copy = try allocator.alloc(u8, options.salt_length);
        @memcpy(salt_copy, salt_slice);
        return DerivedKey{ .key = empty_key, .salt = salt_copy };
    }

    const derived_key_buffer = try allocator.alloc(u8, key_length);
    errdefer allocator.free(derived_key_buffer);

    try std.crypto.pwhash.pbkdf2(
        derived_key_buffer,
        password,
        salt_slice,
        options.iterations,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );

    const allocated_salt_buffer = try allocator.alloc(u8, options.salt_length);
    errdefer allocator.free(allocated_salt_buffer);
    @memcpy(allocated_salt_buffer, salt_slice);

    return DerivedKey{ .key = derived_key_buffer, .salt = allocated_salt_buffer };
}
