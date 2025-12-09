const std = @import("std");
const Salsa20 = @This();

const NONCE_SIZE = 24;
const TAG_SIZE = 16;
const CHUNK_SIZE = 4096;

allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator) Salsa20 {
    return Salsa20{
        .allocator = allocator,
    };
}

pub fn encrypt(_: *Salsa20, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    // 1. Generate and Write Base Nonce
    var base_nonce: [NONCE_SIZE]u8 = undefined;
    std.crypto.random.bytes(&base_nonce);
    try writer.writeAll(&base_nonce);

    var buffer: [CHUNK_SIZE]u8 = undefined;
    var counter: u32 = 0;

    while (true) {
        // 2. Read up to CHUNK_SIZE bytes
        var w: std.Io.Writer = .fixed(&buffer);
        const bytes_read = reader.stream(&w, .limited(CHUNK_SIZE)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (bytes_read == 0) break;

        const plaintext_slice = buffer[0..bytes_read];
        const current_nonce = computeNonce(base_nonce, counter);
        counter += 1;

        // 3. Encrypt
        var tag: [TAG_SIZE]u8 = undefined;
        var ciphertext: [CHUNK_SIZE]u8 = undefined;
        const cipher_slice = ciphertext[0..bytes_read];

        std.crypto.aead.salsa_poly.XSalsa20Poly1305.encrypt(
            cipher_slice,
            &tag,
            plaintext_slice,
            "a",
            current_nonce,
            key[0..32].*,
        );

        // 4. Write Ciphertext + Tag
        try writer.writeAll(cipher_slice);
        try writer.writeAll(&tag);
    }
}

pub fn decrypt(_: *Salsa20, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    // 1. Read Base Nonce
    var base_nonce: [NONCE_SIZE]u8 = undefined;
    try reader.readSliceAll(&base_nonce);

    var read_buffer: [CHUNK_SIZE + TAG_SIZE]u8 = undefined;
    var counter: u32 = 0;

    while (true) {
        // 2. Read chunk + tag
        var w: std.Io.Writer = .fixed(&read_buffer);
        const bytes_read = reader.stream(&w, .limited(CHUNK_SIZE + TAG_SIZE)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (bytes_read == 0) break;
        if (bytes_read < TAG_SIZE) return error.InvalidInput;

        // 3. Separate Ciphertext and Tag
        const data_len = bytes_read - TAG_SIZE;
        const ciphertext = read_buffer[0..data_len];
        const tag = read_buffer[data_len..][0..TAG_SIZE];

        const current_nonce = computeNonce(base_nonce, counter);
        counter += 1;

        var plaintext: [CHUNK_SIZE]u8 = undefined;
        const plaintext_slice = plaintext[0..data_len];

        // 4. Decrypt and Verify
        try std.crypto.aead.salsa_poly.XSalsa20Poly1305.decrypt(
            plaintext_slice,
            ciphertext,
            tag.*,
            "a",
            current_nonce,
            key[0..32].*,
        );

        try writer.writeAll(plaintext_slice);
    }
}

fn computeNonce(base_nonce: [NONCE_SIZE]u8, counter: u32) [NONCE_SIZE]u8 {
    var new_nonce = base_nonce;
    const last_part = std.mem.readInt(u32, base_nonce[20..24], .big);
    const updated = last_part +% counter;
    std.mem.writeInt(u32, new_nonce[20..24], updated, .big);
    return new_nonce;
}
