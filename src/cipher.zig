const std = @import("std");

const CHUNK_SIZE: usize = 64 * 1024;
const MAX_INFLIGHT: usize = 32;
const KDF_PARAMS = std.crypto.pwhash.scrypt.Params{ .ln = 15, .r = 8, .p = 1 };

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
        has_key: bool,
        password: []const u8,
        // Heap-allocated so it is never moved after init
        pool: *std.Thread.Pool,

        pub fn init(allocator: std.mem.Allocator, password: []const u8) !Self {
            const owned_password = try allocator.dupe(u8, password);
            errdefer allocator.free(owned_password);

            const pool = try allocator.create(std.Thread.Pool);
            errdefer allocator.destroy(pool);
            try pool.init(.{ .allocator = allocator });

            return Self{
                .allocator = allocator,
                .key = undefined,
                .salt = undefined,
                .has_key = false,
                .password = owned_password,
                .pool = pool,
            };
        }

        fn ensureKeyForSalt(self: *Self, salt: [32]u8) !void {
            if (self.has_key and std.mem.eql(u8, &self.salt, &salt)) return;

            try std.crypto.pwhash.scrypt.kdf(
                self.allocator,
                &self.key,
                self.password,
                &salt,
                KDF_PARAMS,
            );
            self.salt = salt;
            self.has_key = true;
        }

        pub fn deinit(self: *Self) void {
            self.pool.deinit();
            self.allocator.destroy(self.pool);
            self.allocator.free(self.password);
        }

        pub fn encrypt(self: *Self, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
            var encrypt_salt: [32]u8 = undefined;
            std.crypto.random.bytes(&encrypt_salt);
            try self.ensureKeyForSalt(encrypt_salt);

            try writer.writeAll(&encrypt_salt);

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
                    try self.pool.spawn(struct {
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
            var salt: [32]u8 = undefined;
            try reader.readSliceAll(&salt);
            try self.ensureKeyForSalt(salt);

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
                    try self.pool.spawn(struct {
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
