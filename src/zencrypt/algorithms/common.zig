const std = @import("std");

pub fn BlockCipher(comptime block_size: usize) type {
    return struct {
        pub fn encrypt(
            reader: *std.Io.Reader,
            writer: *std.Io.Writer,
            context: anytype,
            encryptBlock: anytype,
        ) !void {
            var buffer: [block_size]u8 = undefined;

            while (true) {
                var buffer_writer: std.Io.Writer = .fixed(&buffer);
                const bytes_read = reader.stream(&buffer_writer, .limited(block_size)) catch |err|
                    if (err == error.EndOfStream) 0 else return err;

                // PKCS#7 Padding
                if (bytes_read == 0) {
                    // Empty read at start of loop -> previous block was full, so we need a full padding block.
                    @memset(&buffer, @intCast(block_size));
                    encryptBlock(context, &buffer);
                    try writer.writeAll(&buffer);
                    break;
                }

                if (bytes_read < block_size) {
                    const pad_val: u8 = @intCast(block_size - bytes_read);
                    for (bytes_read..block_size) |i| {
                        buffer[i] = pad_val;
                    }
                }

                encryptBlock(context, &buffer);
                try writer.writeAll(&buffer);

                if (bytes_read < block_size) break;
            }
        }

        pub fn decrypt(
            reader: *std.Io.Reader,
            writer: *std.Io.Writer,
            context: anytype,
            decryptBlock: anytype,
        ) !void {
            var prev_block: ?[block_size]u8 = null;
            var buffer: [block_size]u8 = undefined;

            while (true) {
                var buffer_writer: std.Io.Writer = .fixed(&buffer);
                const bytes_read = reader.stream(&buffer_writer, .limited(block_size)) catch |err|
                    if (err == error.EndOfStream) 0 else return err;

                if (bytes_read == 0) break;
                if (bytes_read != block_size) return error.InvalidCiphertextLength;

                decryptBlock(context, &buffer);

                if (prev_block) |prev| {
                    try writer.writeAll(&prev);
                }
                prev_block = buffer;
            }

            if (prev_block) |last| {
                const pad_val = last[block_size - 1];
                if (pad_val == 0 or pad_val > block_size) return error.InvalidPadding;
                for (block_size - pad_val..block_size) |i| {
                    if (last[i] != pad_val) return error.InvalidPadding;
                }
                try writer.writeAll(last[0 .. block_size - pad_val]);
            }
        }
    };
}

pub fn AeadStreamCipher(comptime nonce_size: usize, comptime tag_size: usize, comptime chunk_size: usize) type {
    return struct {
        pub fn encrypt(
            reader: *std.Io.Reader,
            writer: *std.Io.Writer,
            context: anytype,
            computeNonce: anytype,
            encryptChunk: anytype,
        ) !void {
            var base_nonce: [nonce_size]u8 = undefined;
            std.crypto.random.bytes(&base_nonce);
            try writer.writeAll(&base_nonce);

            var buffer: [chunk_size]u8 = undefined;
            var counter: u32 = 0;

            while (true) {
                var w: std.Io.Writer = .fixed(&buffer);
                const bytes_read = reader.stream(&w, .limited(chunk_size)) catch |err|
                    if (err == error.EndOfStream) 0 else return err;

                if (bytes_read == 0) break;

                const plaintext_slice = buffer[0..bytes_read];
                const current_nonce = computeNonce(base_nonce, counter);
                counter += 1;

                var tag: [tag_size]u8 = undefined;
                var ciphertext: [chunk_size]u8 = undefined;
                const cipher_slice = ciphertext[0..bytes_read];

                encryptChunk(context, current_nonce, plaintext_slice, cipher_slice, &tag);

                try writer.writeAll(cipher_slice);
                try writer.writeAll(&tag);
            }
        }

        pub fn decrypt(
            reader: *std.Io.Reader,
            writer: *std.Io.Writer,
            context: anytype,
            computeNonce: anytype,
            decryptChunk: anytype,
        ) !void {
            var base_nonce: [nonce_size]u8 = undefined;
            try reader.readSliceAll(&base_nonce);

            var read_buffer: [chunk_size + tag_size]u8 = undefined;
            var counter: u32 = 0;

            while (true) {
                var w: std.Io.Writer = .fixed(&read_buffer);
                const bytes_read = reader.stream(&w, .limited(chunk_size + tag_size)) catch |err|
                    if (err == error.EndOfStream) 0 else return err;

                if (bytes_read == 0) break;
                if (bytes_read < tag_size) return error.InvalidInput;

                const data_len = bytes_read - tag_size;
                const ciphertext = read_buffer[0..data_len];
                const tag = read_buffer[data_len..][0..tag_size];

                const current_nonce = computeNonce(base_nonce, counter);
                counter += 1;

                var plaintext: [chunk_size]u8 = undefined;
                const plaintext_slice = plaintext[0..data_len];

                try decryptChunk(context, current_nonce, ciphertext, tag.*, plaintext_slice);

                try writer.writeAll(plaintext_slice);
            }
        }
    };
}
