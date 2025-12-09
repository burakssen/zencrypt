const std = @import("std");
const AesGcm = @This();

pub const AesGcmType = enum {
    AesGcm128,
    AesGcm256,
};

// Standard chunk size (4KB is efficient for disk I/O)
const CHUNK_SIZE = 4096;
const TAG_SIZE = 16;
const NONCE_SIZE = 12;

allocator: std.mem.Allocator,
aes_gcm_type: AesGcmType,

pub fn init(allocator: std.mem.Allocator, aes_gcm_type: AesGcmType) AesGcm {
    return AesGcm{
        .allocator = allocator,
        .aes_gcm_type = aes_gcm_type,
    };
}
pub fn encrypt(self: *AesGcm, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    // 1. Generate and Write Base Nonce
    var base_nonce: [NONCE_SIZE]u8 = undefined;
    std.crypto.random.bytes(&base_nonce);
    try writer.writeAll(&base_nonce);

    var buffer: [CHUNK_SIZE]u8 = undefined;
    var counter: u32 = 0;

    while (true) {
        // 3. Read up to CHUNK_SIZE bytes
        // We use 'read' because we want to fill the chunk if possible,
        // but if it's the end of the file, we get a partial read.
        var buffer_writer: std.Io.Writer = .fixed(&buffer);
        const bytes_read = reader.stream(&buffer_writer, .limited(16)) catch |err|
            if (err == error.EndOfStream) 0 else return err;
        if (bytes_read == 0) break;

        const plaintext_slice = buffer[0..bytes_read];
        const current_nonce = computeNonce(base_nonce, counter);
        counter += 1;

        // 4. Encrypt
        var tag: [TAG_SIZE]u8 = undefined;
        // Output buffer must match input size
        var ciphertext: [CHUNK_SIZE]u8 = undefined;
        const cipher_slice = ciphertext[0..bytes_read];

        switch (self.aes_gcm_type) {
            .AesGcm128 => {
                if (key.len != 16) return error.InvalidKeyLength;
                std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(cipher_slice, &tag, plaintext_slice, "a", current_nonce, key[0..16].*);
            },
            .AesGcm256 => {
                if (key.len != 32) return error.InvalidKeyLength;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(cipher_slice, &tag, plaintext_slice, "a", current_nonce, key[0..32].*);
            },
        }

        // 5. Write Ciphertext + Tag
        try writer.writeAll(cipher_slice);
        try writer.writeAll(&tag);
    }
}
pub fn decrypt(self: *AesGcm, reader: *std.Io.Reader, writer: *std.Io.Writer, key: []const u8) !void {
    // 1. Read Base Nonce
    var base_nonce: [NONCE_SIZE]u8 = undefined;
    // Ensure we actually read 12 bytes. If not, it's invalid.
    try reader.readSliceAll(&base_nonce);

    var read_buffer: [CHUNK_SIZE + TAG_SIZE]u8 = undefined;
    var counter: u32 = 0;

    while (true) {
        // 2. Read the stream.
        // We must attempt to fill the buffer completely (CHUNK + TAG).
        // If we get a partial read that is NOT EOF, we must keep reading.
        // If we hit EOF, that partial read is the last chunk.

        var buffer_writer: std.Io.Writer = .fixed(&read_buffer);
        const bytes_read = reader.stream(&buffer_writer, .limited(CHUNK_SIZE + TAG_SIZE)) catch |err|
            if (err == error.EndOfStream) 0 else return err;

        if (bytes_read == 0) break; // Done
        if (bytes_read < TAG_SIZE) return error.InvalidInput; // Too short to have a tag

        // Separate Ciphertext and Tag
        // The tag is ALWAYS the last 16 bytes of the block we just read.
        const data_len = bytes_read - TAG_SIZE;
        const ciphertext = read_buffer[0..data_len];
        const tag = read_buffer[data_len..][0..TAG_SIZE];

        const current_nonce = computeNonce(base_nonce, counter);
        counter += 1;

        var plaintext: [CHUNK_SIZE]u8 = undefined;
        const plaintext_slice = plaintext[0..data_len];

        // 3. Decrypt and Verify
        switch (self.aes_gcm_type) {
            .AesGcm128 => {
                if (key.len != 16) return error.InvalidKeyLength;
                try std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(plaintext_slice, ciphertext, tag.*, "a", current_nonce, key[0..16].*);
            },
            .AesGcm256 => {
                if (key.len != 32) return error.InvalidKeyLength;
                try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext_slice, ciphertext, tag.*, "a", current_nonce, key[0..32].*);
            },
        }

        try writer.writeAll(plaintext_slice);
    }
}

fn computeNonce(base_nonce: [NONCE_SIZE]u8, counter: u32) [NONCE_SIZE]u8 {
    var new_nonce = base_nonce;
    const last_part = std.mem.readInt(u32, base_nonce[8..12], .big);
    // Use wrapping addition
    const updated = last_part +% counter;
    std.mem.writeInt(u32, new_nonce[8..12], updated, .big);
    return new_nonce;
}

test "Streaming Chunked GCM" {
    const allocator = std.testing.allocator;
    var gcm = AesGcm.init(allocator, .AesGcm256);
    const key = "12345678901234567890123456789012";

    // Create data larger than one chunk (4096) to test loop
    const input_data = "A" ** 5000;

    // Encrypt
    var in_stream: std.Io.Reader = .fixed(input_data);
    var out_list: std.Io.Writer.Allocating = .init(allocator);
    defer out_list.deinit();

    try gcm.encrypt(&in_stream, &out_list.writer, key);

    // Decrypt
    var dec_in_stream: std.Io.Reader = .fixed(out_list.written());
    var dec_out_list: std.Io.Writer.Allocating = .init(allocator);
    defer dec_out_list.deinit();

    try gcm.decrypt(&dec_in_stream, &dec_out_list.writer, key);
    try std.testing.expectEqualStrings(input_data, dec_out_list.written());
}
