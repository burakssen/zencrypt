const std = @import("std");

pub fn BlockCipher(comptime block_size: usize) type {
    return struct {
        const Job = struct {
            block: [block_size]u8,
            index: usize,
            is_last: bool,
            bytes_read: usize,
        };

        allocator: std.mem.Allocator,
        pool: std.Thread.Pool = undefined,

        pub fn init(allocator: std.mem.Allocator) @This() {
            return .{
                .allocator = allocator,
            };
        }

        pub fn encrypt(
            self: *@This(),
            reader: *std.Io.Reader,
            writer: *std.Io.Writer,
            context: anytype,
            encryptBlock: anytype,
        ) !void {
            try self.pool.init(.{ .allocator = self.allocator, .n_jobs = 4 });
            defer self.pool.deinit();

            var jobs: std.ArrayList(Job) = .empty;
            defer jobs.deinit(self.allocator);

            var mutex = std.Thread.Mutex{};
            var wait_group: std.Thread.WaitGroup = .{};
            var index: usize = 0;

            // Read all blocks
            var buffer: [block_size]u8 = undefined;
            while (true) {
                const bytes_read = reader.readSliceShort(&buffer) catch |err|
                    if (err == error.EndOfStream) 0 else return err;

                if (bytes_read == 0) {
                    // Need full padding block
                    @memset(&buffer, @intCast(block_size));
                    try jobs.append(self.allocator, .{
                        .block = buffer,
                        .index = index,
                        .is_last = true,
                        .bytes_read = block_size,
                    });
                    break;
                }

                // Apply PKCS#7 padding if needed
                if (bytes_read < block_size) {
                    const pad_val: u8 = @intCast(block_size - bytes_read);
                    for (bytes_read..block_size) |i| {
                        buffer[i] = pad_val;
                    }
                }

                try jobs.append(self.allocator, .{
                    .block = buffer,
                    .index = index,
                    .is_last = bytes_read < block_size,
                    .bytes_read = bytes_read,
                });

                index += 1;
                if (bytes_read < block_size) break;
            }

            // Encrypt blocks in parallel
            for (jobs.items) |*job| {
                wait_group.start();
                try self.pool.spawn(struct {
                    fn work(ctx: anytype, blk: *[block_size]u8, mtx: *std.Thread.Mutex, wg: *std.Thread.WaitGroup) void {
                        defer wg.finish();
                        mtx.lock();
                        defer mtx.unlock();
                        encryptBlock(ctx, blk);
                    }
                }.work, .{ context, &job.block, &mutex, &wait_group });
            }

            self.pool.waitAndWork(&wait_group);

            // Write blocks in order
            for (jobs.items) |job| {
                try writer.writeAll(&job.block);
            }
        }

        pub fn decrypt(
            self: *@This(),
            reader: *std.Io.Reader,
            writer: *std.Io.Writer,
            context: anytype,
            decryptBlock: anytype,
        ) !void {
            try self.pool.init(.{ .allocator = self.allocator, .n_jobs = 4 });
            defer self.pool.deinit();
            var jobs: std.ArrayList(Job) = .empty;
            defer jobs.deinit(self.allocator);
            var mutex = std.Thread.Mutex{};
            var wait_group: std.Thread.WaitGroup = .{};
            var index: usize = 0;

            // Read all blocks
            var buffer: [block_size]u8 = undefined;
            while (true) {
                const bytes_read = reader.readSliceShort(&buffer) catch |err|
                    if (err == error.EndOfStream) 0 else return err;

                if (bytes_read == 0) break;
                if (bytes_read != block_size) return error.InvalidCiphertextLength;

                try jobs.append(self.allocator, .{
                    .block = buffer,
                    .index = index,
                    .is_last = false,
                    .bytes_read = bytes_read,
                });
                index += 1;
            }

            if (jobs.items.len > 0) {
                jobs.items[jobs.items.len - 1].is_last = true;
            }

            // Decrypt blocks in parallel
            for (jobs.items) |*job| {
                wait_group.start();
                try self.pool.spawn(struct {
                    fn work(ctx: anytype, blk: *[block_size]u8, mtx: *std.Thread.Mutex, wg: *std.Thread.WaitGroup) void {
                        defer wg.finish();
                        mtx.lock();
                        defer mtx.unlock();
                        decryptBlock(ctx, blk);
                    }
                }.work, .{ context, &job.block, &mutex, &wait_group });
            }

            self.pool.waitAndWork(&wait_group);

            // Write blocks in order, handling padding on last block
            for (jobs.items) |job| {
                if (job.is_last) {
                    const pad_val = job.block[block_size - 1];
                    if (pad_val == 0 or pad_val > block_size) return error.InvalidPadding;
                    for (block_size - pad_val..block_size) |j| {
                        if (job.block[j] != pad_val) return error.InvalidPadding;
                    }
                    try writer.writeAll(job.block[0 .. block_size - pad_val]);
                } else {
                    try writer.writeAll(&job.block);
                }
            }
        }
    };
}

pub fn AeadStreamCipher(comptime nonce_size: usize, comptime tag_size: usize, comptime chunk_size: usize) type {
    return struct {
        const Job = struct {
            data: [chunk_size]u8,
            tag: [tag_size]u8,
            nonce: [nonce_size]u8,
            index: usize,
            len: usize,
        };

        allocator: std.mem.Allocator,
        pool: std.Thread.Pool = undefined,

        pub fn init(allocator: std.mem.Allocator) @This() {
            return .{
                .allocator = allocator,
            };
        }

        pub fn encrypt(
            self: *@This(),
            reader: *std.Io.Reader,
            writer: *std.Io.Writer,
            context: anytype,
            computeNonce: anytype,
            encryptChunk: anytype,
        ) !void {
            var base_nonce: [nonce_size]u8 = undefined;
            std.crypto.random.bytes(&base_nonce);
            try writer.writeAll(&base_nonce);

            try self.pool.init(.{ .allocator = self.allocator, .n_jobs = 4 });
            defer self.pool.deinit();
            var jobs: std.ArrayList(Job) = .empty;
            defer jobs.deinit(self.allocator);

            var mutex = std.Thread.Mutex{};
            var wait_group: std.Thread.WaitGroup = .{};
            var counter: u32 = 0;

            // Read all chunks
            var buffer: [chunk_size]u8 = undefined;
            while (true) {
                const bytes_read = reader.readSliceShort(&buffer) catch |err|
                    if (err == error.EndOfStream) 0 else return err;

                if (bytes_read == 0) break;

                const current_nonce = computeNonce(base_nonce, counter);
                try jobs.append(self.allocator, .{
                    .data = buffer,
                    .tag = undefined,
                    .nonce = current_nonce,
                    .index = counter,
                    .len = bytes_read,
                });
                counter += 1;
            }

            // Encrypt chunks in parallel
            for (jobs.items) |*job| {
                wait_group.start();
                try self.pool.spawn(struct {
                    fn work(ctx: anytype, j: *Job, mtx: *std.Thread.Mutex, wg: *std.Thread.WaitGroup, encFn: anytype) void {
                        defer wg.finish();
                        var ciphertext: [chunk_size]u8 = undefined;
                        const plaintext_slice = j.data[0..j.len];
                        const cipher_slice = ciphertext[0..j.len];

                        mtx.lock();
                        defer mtx.unlock();
                        encFn(ctx, j.nonce, plaintext_slice, cipher_slice, &j.tag);
                        @memcpy(j.data[0..j.len], cipher_slice);
                    }
                }.work, .{ context, job, &mutex, &wait_group, encryptChunk });
            }

            self.pool.waitAndWork(&wait_group);

            // Write chunks in order
            for (jobs.items) |job| {
                try writer.writeAll(job.data[0..job.len]);
                try writer.writeAll(&job.tag);
            }
        }

        pub fn decrypt(
            self: *@This(),
            reader: *std.Io.Reader,
            writer: *std.Io.Writer,
            context: anytype,
            computeNonce: anytype,
            decryptChunk: anytype,
        ) !void {
            var base_nonce: [nonce_size]u8 = undefined;
            try reader.readSliceAll(&base_nonce);

            try self.pool.init(.{ .allocator = self.allocator, .n_jobs = 4 });
            defer self.pool.deinit();
            var jobs: std.ArrayList(Job) = .empty;
            defer jobs.deinit(self.allocator);

            var mutex = std.Thread.Mutex{};
            var wait_group: std.Thread.WaitGroup = .{};
            var counter: u32 = 0;

            // Read all chunks
            var read_buffer: [chunk_size + tag_size]u8 = undefined;

            while (true) {
                const bytes_read = reader.readSliceShort(&read_buffer) catch |err|
                    if (err == error.EndOfStream) 0 else return err;

                if (bytes_read == 0) break;
                if (bytes_read < tag_size) return error.InvalidInput;

                const data_len = bytes_read - tag_size;
                var job = Job{
                    .data = undefined,
                    .tag = undefined,
                    .nonce = computeNonce(base_nonce, counter),
                    .index = counter,
                    .len = data_len,
                };

                @memcpy(job.data[0..data_len], read_buffer[0..data_len]);
                @memcpy(&job.tag, read_buffer[data_len..][0..tag_size]);

                try jobs.append(self.allocator, job);
                counter += 1;
            }

            // Decrypt chunks in parallel
            for (jobs.items) |*job| {
                wait_group.start();

                try self.pool.spawn(struct {
                    fn work(ctx: anytype, j: *Job, mtx: *std.Thread.Mutex, wg: *std.Thread.WaitGroup, decFn: anytype) void {
                        defer wg.finish();
                        var plaintext: [chunk_size]u8 = undefined;
                        const ciphertext = j.data[0..j.len];
                        const plaintext_slice = plaintext[0..j.len];

                        mtx.lock();
                        defer mtx.unlock();
                        decFn(ctx, j.nonce, ciphertext, j.tag, plaintext_slice) catch {
                            std.debug.print("Decryption failed for chunk {d}\n", .{j.index});
                            return;
                        };
                        @memcpy(j.data[0..j.len], plaintext_slice);
                    }
                }.work, .{ context, job, &mutex, &wait_group, decryptChunk });
            }

            self.pool.waitAndWork(&wait_group);

            // Write chunks in order
            for (jobs.items) |job| {
                try writer.writeAll(job.data[0..job.len]);
            }
        }
    };
}
