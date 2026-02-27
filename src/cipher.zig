const std = @import("std");

const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
const MAX_INFLIGHT: usize = 8; // chunks in flight at once

pub fn Cipher(comptime C: type) type {
    return struct {
        const Self = @This();

        const EncryptJob = struct {
            plaintext: []u8,
            ciphertext: []u8,
            tag: [C.tag_length]u8,
            nonce: [C.nonce_length]u8,
            len: usize,
            key: *const [32]u8,
            done: std.atomic.Value(bool),

            fn run(job: *EncryptJob) void {
                const chunk = job.plaintext[0..job.len];
                const out = job.ciphertext[0..job.len];
                C.encrypt(out, &job.tag, chunk, "", job.nonce, job.key.*);
                job.done.store(true, .release);
            }
        };

        const DecryptJob = struct {
            plaintext: []u8,
            ciphertext: []u8,
            tag: [C.tag_length]u8,
            nonce: [C.nonce_length]u8,
            len: usize,
            key: *const [32]u8,
            done: std.atomic.Value(bool),
            err: ?anyerror,

            fn run(job: *DecryptJob) void {
                const ct = job.ciphertext[0..job.len];
                const pt = job.plaintext[0..job.len];
                C.decrypt(pt, ct, job.tag, "", job.nonce, job.key.*) catch |e| {
                    job.err = e;
                    job.done.store(true, .release);
                    return;
                };
                job.err = null;
                job.done.store(true, .release);
            }
        };

        allocator: std.mem.Allocator,
        key: [32]u8,
        salt: [32]u8,
        password: []const u8,

        pub fn init(allocator: std.mem.Allocator, password: []const u8) !Self {
            var salt: [32]u8 = undefined;
            std.crypto.random.bytes(&salt);
            var key: [32]u8 = undefined;
            try std.crypto.pwhash.scrypt.kdf(
                allocator,
                &key,
                password,
                &salt,
                .{ .ln = 15, .r = 8, .p = 1 },
            );
            // Dupe password so we can re-derive the key during decrypt
            const owned_password = try allocator.dupe(u8, password);
            return Self{ .allocator = allocator, .key = key, .salt = salt, .password = owned_password };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.password);
        }

        pub fn initFromPassword(allocator: std.mem.Allocator, password: []const u8, salt: [32]u8) !Self {
            var key: [32]u8 = undefined;
            try std.crypto.pwhash.scrypt.kdf(
                allocator,
                &key,
                password,
                &salt,
                .{ .ln = 15, .r = 8, .p = 1 },
            );
            const owned_password = try allocator.dupe(u8, password);
            return Self{ .allocator = allocator, .key = key, .salt = salt, .password = owned_password };
        }

        pub fn encrypt(self: *Self, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
            try writer.writeAll(&self.salt);

            var jobs: [MAX_INFLIGHT]EncryptJob = undefined;
            for (&jobs) |*job| {
                job.plaintext = try self.allocator.alloc(u8, CHUNK_SIZE);
                job.ciphertext = try self.allocator.alloc(u8, CHUNK_SIZE);
                job.done = std.atomic.Value(bool).init(false);
                job.key = &self.key;
            }
            defer for (&jobs) |*job| {
                self.allocator.free(job.plaintext);
                self.allocator.free(job.ciphertext);
            };

            var pool: std.Thread.Pool = undefined;
            try pool.init(.{ .allocator = self.allocator });
            defer pool.deinit();

            var wg: std.Thread.WaitGroup = .{};
            var head: usize = 0;
            var tail: usize = 0;
            var total_read: usize = 0;
            var eof = false;

            while (!eof or head != tail) {
                while (!eof and (head - tail) < MAX_INFLIGHT) {
                    const slot = head % MAX_INFLIGHT;
                    const job = &jobs[slot];

                    var total: usize = 0;
                    while (total < CHUNK_SIZE) {
                        const n = try reader.readSliceShort(job.plaintext[total..]);
                        if (n == 0) {
                            eof = true;
                            break;
                        }
                        total += n;
                    }

                    if (total == 0) break;
                    total_read += total;
                    job.len = total;
                    job.done.store(false, .release);
                    std.crypto.random.bytes(&job.nonce);

                    wg.start();
                    try pool.spawn(struct {
                        fn call(j: *EncryptJob, w: *std.Thread.WaitGroup) void {
                            defer w.finish();
                            j.run();
                        }
                    }.call, .{ job, &wg });

                    head += 1;
                }

                if (head != tail) {
                    const slot = tail % MAX_INFLIGHT;
                    const job = &jobs[slot];

                    while (!job.done.load(.acquire)) {
                        std.atomic.spinLoopHint();
                    }

                    try writer.writeInt(u32, @intCast(job.len), .little);
                    try writer.writeAll(&job.nonce);
                    try writer.writeAll(&job.tag);
                    try writer.writeAll(job.ciphertext[0..job.len]);

                    tail += 1;
                }
            }

            wg.wait();
            if (total_read == 0) return error.EmptyInput;
            try writer.flush();
        }

        pub fn decrypt(self: *Self, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
            // Read the salt that was written by encrypt
            var salt: [32]u8 = undefined;
            try reader.readSliceAll(&salt);

            // Re-derive the key using the stored password and the salt from the stream
            try std.crypto.pwhash.scrypt.kdf(
                self.allocator,
                &self.key,
                self.password,
                &salt,
                .{ .ln = 15, .r = 8, .p = 1 },
            );
            self.salt = salt;

            var jobs: [MAX_INFLIGHT]DecryptJob = undefined;
            for (&jobs) |*job| {
                job.plaintext = try self.allocator.alloc(u8, CHUNK_SIZE);
                job.ciphertext = try self.allocator.alloc(u8, CHUNK_SIZE);
                job.done = std.atomic.Value(bool).init(false);
                job.key = &self.key;
            }
            defer for (&jobs) |*job| {
                self.allocator.free(job.plaintext);
                self.allocator.free(job.ciphertext);
            };

            var pool: std.Thread.Pool = undefined;
            try pool.init(.{ .allocator = self.allocator });
            defer pool.deinit();

            var wg: std.Thread.WaitGroup = .{};
            var head: usize = 0;
            var tail: usize = 0;
            var total_read: usize = 0;
            var eof = false;

            while (!eof or head != tail) {
                while (!eof and (head - tail) < MAX_INFLIGHT) {
                    const slot = head % MAX_INFLIGHT;
                    const job = &jobs[slot];

                    const chunk_len = reader.takeInt(u32, .little) catch |err| switch (err) {
                        error.EndOfStream => {
                            eof = true;
                            break;
                        },
                        else => return err,
                    };

                    if (chunk_len == 0 or chunk_len > CHUNK_SIZE) return error.InvalidChunkSize;

                    job.len = chunk_len;
                    job.done.store(false, .release);
                    job.err = null;
                    total_read += chunk_len;

                    try reader.readSliceAll(&job.nonce);
                    try reader.readSliceAll(&job.tag);
                    try reader.readSliceAll(job.ciphertext[0..chunk_len]);

                    wg.start();
                    try pool.spawn(struct {
                        fn call(j: *DecryptJob, w: *std.Thread.WaitGroup) void {
                            defer w.finish();
                            j.run();
                        }
                    }.call, .{ job, &wg });

                    head += 1;
                }

                if (head != tail) {
                    const slot = tail % MAX_INFLIGHT;
                    const job = &jobs[slot];

                    while (!job.done.load(.acquire)) {
                        std.atomic.spinLoopHint();
                    }

                    if (job.err) |e| return e;
                    try writer.writeAll(job.plaintext[0..job.len]);

                    tail += 1;
                }
            }

            wg.wait();
            if (total_read == 0) return error.EmptyInput;
            try writer.flush();
        }
    };
}
