const std = @import("std");
const zencrypt = @import("zencrypt");
const stress_options = @import("stress_options");

const CHUNK_BOUNDARY: usize = 64 * 1024;
const NS_PER_S_I128: i128 = 1_000_000_000;
const PASSWORD: []const u8 = "stress-password";
const PERF_PHASE_NUM: i128 = 4;
const PERF_PHASE_DEN: i128 = 5;

const Workload = struct {
    name: []const u8,
    base_size: usize,
};

const perf_workload_table = [_]Workload{
    .{ .name = "perf-1m", .base_size = 1 * 1024 * 1024 },
    .{ .name = "perf-2m", .base_size = 2 * 1024 * 1024 },
    .{ .name = "perf-4m", .base_size = 4 * 1024 * 1024 },
};

const reliability_workload_table = [_]Workload{
    .{ .name = "tiny", .base_size = 31 },
    .{ .name = "small", .base_size = 1024 },
    .{ .name = "medium", .base_size = 128 * 1024 },
    .{ .name = "chunk-minus-1", .base_size = CHUNK_BOUNDARY - 1 },
    .{ .name = "chunk", .base_size = CHUNK_BOUNDARY },
    .{ .name = "chunk-plus-1", .base_size = CHUNK_BOUNDARY + 1 },
    .{ .name = "large", .base_size = 2 * 1024 * 1024 },
};

const PhaseMetrics = struct {
    roundtrip_ops: u64 = 0,
    tamper_checks: u64 = 0,
    bytes_processed: u64 = 0,
};

const FailureInfo = struct {
    worker_id: usize,
    stage: []const u8,
    err: anyerror,
    algorithm: zencrypt.ZEncryptType,
    workload_name: []const u8,
};

const SharedState = struct {
    lock: std.Thread.Mutex = .{},
    perf_metrics: [2]PhaseMetrics = .{ .{}, .{} },
    reliability_metrics: [2]PhaseMetrics = .{ .{}, .{} },
    failures: u64 = 0,
    first_failure: ?FailureInfo = null,
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn recordPerfRoundtrip(self: *SharedState, algorithm: zencrypt.ZEncryptType, bytes: usize) void {
        self.lock.lock();
        defer self.lock.unlock();

        const idx = algorithmIndex(algorithm);
        self.perf_metrics[idx].roundtrip_ops += 1;
        self.perf_metrics[idx].bytes_processed += bytes;
    }

    fn recordReliabilityRoundtrip(self: *SharedState, algorithm: zencrypt.ZEncryptType, bytes: usize) void {
        self.lock.lock();
        defer self.lock.unlock();

        const idx = algorithmIndex(algorithm);
        self.reliability_metrics[idx].roundtrip_ops += 1;
        self.reliability_metrics[idx].bytes_processed += bytes;
    }

    fn recordTamper(self: *SharedState, algorithm: zencrypt.ZEncryptType) void {
        self.lock.lock();
        defer self.lock.unlock();

        const idx = algorithmIndex(algorithm);
        self.reliability_metrics[idx].tamper_checks += 1;
    }

    fn recordFailure(
        self: *SharedState,
        worker_id: usize,
        stage: []const u8,
        err: anyerror,
        algorithm: zencrypt.ZEncryptType,
        workload_name: []const u8,
    ) void {
        self.failed.store(true, .release);

        self.lock.lock();
        defer self.lock.unlock();

        self.failures += 1;
        if (self.first_failure == null) {
            self.first_failure = .{
                .worker_id = worker_id,
                .stage = stage,
                .err = err,
                .algorithm = algorithm,
                .workload_name = workload_name,
            };
        }
    }
};

const WorkerContext = struct {
    id: usize,
    perf_deadline_ns: i128,
    final_deadline_ns: i128,
    scale: u32,
    shared: *SharedState,
};

const TamperResult = enum {
    rejected,
    accepted,
};

const Summary = struct {
    elapsed_seconds: f64,
    perf_throughput_mib_s: f64,
    reliability_throughput_mib_s: f64,
};

const CipherPair = struct {
    encryptor: *zencrypt.ZEncrypt,
    decryptor: *zencrypt.ZEncrypt,
};

pub fn main() !void {
    const stress_seconds = if (stress_options.stress_seconds == 0) @as(u32, 1) else stress_options.stress_seconds;
    const worker_count_u32 = if (stress_options.stress_workers == 0) @as(u32, 1) else stress_options.stress_workers;
    const stress_scale = if (stress_options.stress_scale == 0) @as(u32, 1) else stress_options.stress_scale;
    const worker_count: usize = @intCast(worker_count_u32);

    const total_duration_ns = @as(i128, @intCast(stress_seconds)) * NS_PER_S_I128;
    const perf_duration_ns = if (total_duration_ns <= 1) total_duration_ns else (total_duration_ns * PERF_PHASE_NUM) / PERF_PHASE_DEN;
    const reliability_duration_ns = total_duration_ns - perf_duration_ns;

    const start_ns = std.time.nanoTimestamp();
    const perf_deadline_ns = start_ns + perf_duration_ns;
    const final_deadline_ns = perf_deadline_ns + reliability_duration_ns;

    var shared = SharedState{};

    var workers = try std.heap.page_allocator.alloc(std.Thread, worker_count);
    defer std.heap.page_allocator.free(workers);

    var contexts = try std.heap.page_allocator.alloc(WorkerContext, worker_count);
    defer std.heap.page_allocator.free(contexts);

    var i: usize = 0;
    while (i < worker_count) : (i += 1) {
        contexts[i] = .{
            .id = i,
            .perf_deadline_ns = perf_deadline_ns,
            .final_deadline_ns = final_deadline_ns,
            .scale = stress_scale,
            .shared = &shared,
        };
        workers[i] = try std.Thread.spawn(.{}, workerMain, .{&contexts[i]});
    }

    for (workers) |*worker| worker.join();

    const end_ns = std.time.nanoTimestamp();
    const elapsed_ns = if (end_ns > start_ns) end_ns - start_ns else 0;

    const summary = printSummary(
        &shared,
        elapsed_ns,
        perf_duration_ns,
        reliability_duration_ns,
        stress_seconds,
        worker_count,
        stress_scale,
    );

    if (shared.failed.load(.acquire)) return error.StressValidationFailed;

    if (stress_options.stress_enforce_throughput_gate and summary.perf_throughput_mib_s < stress_options.stress_min_throughput_mib) {
        std.debug.print(
            "performance gate failed: required={d:.2} MiB/s measured={d:.2} MiB/s\n",
            .{ stress_options.stress_min_throughput_mib, summary.perf_throughput_mib_s },
        );
        return error.PerformanceBelowTarget;
    }
}

fn workerMain(ctx: *WorkerContext) void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var aes_encryptor = zencrypt.ZEncrypt.init(allocator, .aes, PASSWORD) catch |err| {
        ctx.shared.recordFailure(ctx.id, "init-aes-encryptor", err, .aes, "n/a");
        return;
    };
    defer aes_encryptor.deinit();

    var aes_decryptor = zencrypt.ZEncrypt.init(allocator, .aes, PASSWORD) catch |err| {
        ctx.shared.recordFailure(ctx.id, "init-aes-decryptor", err, .aes, "n/a");
        return;
    };
    defer aes_decryptor.deinit();

    var xchacha_encryptor = zencrypt.ZEncrypt.init(allocator, .xchacha20, PASSWORD) catch |err| {
        ctx.shared.recordFailure(ctx.id, "init-xchacha-encryptor", err, .xchacha20, "n/a");
        return;
    };
    defer xchacha_encryptor.deinit();

    var xchacha_decryptor = zencrypt.ZEncrypt.init(allocator, .xchacha20, PASSWORD) catch |err| {
        ctx.shared.recordFailure(ctx.id, "init-xchacha-decryptor", err, .xchacha20, "n/a");
        return;
    };
    defer xchacha_decryptor.deinit();

    const max_payload_size = scaledPayloadSize(maxBasePayloadSize(), ctx.scale) catch |err| {
        ctx.shared.recordFailure(ctx.id, "max-payload-size", err, .aes, "n/a");
        return;
    };

    const payload_buf = allocator.alloc(u8, max_payload_size) catch |err| {
        ctx.shared.recordFailure(ctx.id, "alloc-payload-buffer", err, .aes, "n/a");
        return;
    };
    defer allocator.free(payload_buf);

    var prng = std.Random.DefaultPrng.init(workerSeed(ctx.id));
    const random = prng.random();

    var perf_workload_index: usize = ctx.id % perf_workload_table.len;
    var reliability_workload_index: usize = ctx.id % reliability_workload_table.len;
    var use_aes = (ctx.id % 2) == 0;

    while (std.time.nanoTimestamp() < ctx.perf_deadline_ns and !ctx.shared.failed.load(.acquire)) {
        const workload = perf_workload_table[perf_workload_index];
        perf_workload_index = (perf_workload_index + 1) % perf_workload_table.len;

        const algorithm: zencrypt.ZEncryptType = if (use_aes) .aes else .xchacha20;
        use_aes = !use_aes;

        const payload_size = scaledPayloadSize(workload.base_size, ctx.scale) catch |err| {
            ctx.shared.recordFailure(ctx.id, "scale-perf-payload", err, algorithm, workload.name);
            return;
        };
        const payload = payload_buf[0..payload_size];
        random.bytes(payload);

        const pair = selectCipherPair(algorithm, &aes_encryptor, &aes_decryptor, &xchacha_encryptor, &xchacha_decryptor);
        runRoundtrip(allocator, pair.encryptor, pair.decryptor, payload) catch |err| {
            ctx.shared.recordFailure(ctx.id, "perf-roundtrip", err, algorithm, workload.name);
            return;
        };
        ctx.shared.recordPerfRoundtrip(algorithm, payload.len);
    }

    while (std.time.nanoTimestamp() < ctx.final_deadline_ns and !ctx.shared.failed.load(.acquire)) {
        const workload = reliability_workload_table[reliability_workload_index];
        reliability_workload_index = (reliability_workload_index + 1) % reliability_workload_table.len;

        const algorithm: zencrypt.ZEncryptType = if (use_aes) .aes else .xchacha20;
        use_aes = !use_aes;

        const payload_size = scaledPayloadSize(workload.base_size, ctx.scale) catch |err| {
            ctx.shared.recordFailure(ctx.id, "scale-reliability-payload", err, algorithm, workload.name);
            return;
        };
        const payload = payload_buf[0..payload_size];
        random.bytes(payload);

        const pair = selectCipherPair(algorithm, &aes_encryptor, &aes_decryptor, &xchacha_encryptor, &xchacha_decryptor);
        runRoundtrip(allocator, pair.encryptor, pair.decryptor, payload) catch |err| {
            ctx.shared.recordFailure(ctx.id, "reliability-roundtrip", err, algorithm, workload.name);
            return;
        };
        ctx.shared.recordReliabilityRoundtrip(algorithm, payload.len);

        const tamper_result = runTamperCheck(allocator, pair.encryptor, pair.decryptor, payload) catch |err| {
            ctx.shared.recordFailure(ctx.id, "tamper-check", err, algorithm, workload.name);
            return;
        };
        switch (tamper_result) {
            .rejected => ctx.shared.recordTamper(algorithm),
            .accepted => {
                ctx.shared.recordFailure(ctx.id, "tamper-accepted", error.TamperAccepted, algorithm, workload.name);
                return;
            },
        }
    }
}

fn selectCipherPair(
    algorithm: zencrypt.ZEncryptType,
    aes_encryptor: *zencrypt.ZEncrypt,
    aes_decryptor: *zencrypt.ZEncrypt,
    xchacha_encryptor: *zencrypt.ZEncrypt,
    xchacha_decryptor: *zencrypt.ZEncrypt,
) CipherPair {
    return switch (algorithm) {
        .aes => .{ .encryptor = aes_encryptor, .decryptor = aes_decryptor },
        .xchacha20 => .{ .encryptor = xchacha_encryptor, .decryptor = xchacha_decryptor },
    };
}

fn runRoundtrip(
    allocator: std.mem.Allocator,
    encryptor: *zencrypt.ZEncrypt,
    decryptor: *zencrypt.ZEncrypt,
    plaintext: []const u8,
) !void {
    const encrypted = try encryptPayload(allocator, encryptor, plaintext);
    defer allocator.free(encrypted);

    const decrypted = try decryptPayload(allocator, decryptor, encrypted);
    defer allocator.free(decrypted);

    if (!std.mem.eql(u8, plaintext, decrypted)) return error.RoundtripMismatch;
}

fn runTamperCheck(
    allocator: std.mem.Allocator,
    encryptor: *zencrypt.ZEncrypt,
    decryptor: *zencrypt.ZEncrypt,
    plaintext: []const u8,
) !TamperResult {
    const encrypted = try encryptPayload(allocator, encryptor, plaintext);
    defer allocator.free(encrypted);

    var tampered = try allocator.dupe(u8, encrypted);
    defer allocator.free(tampered);

    if (tampered.len == 0) return error.EmptyCiphertext;

    tampered[tampered.len - 1] ^= 0x01;

    var in_stream: std.Io.Reader = .fixed(tampered);
    var out_buf: std.Io.Writer.Allocating = .init(allocator);
    defer out_buf.deinit();

    decryptor.decrypt(&in_stream, &out_buf.writer) catch {
        return .rejected;
    };

    return .accepted;
}

fn encryptPayload(allocator: std.mem.Allocator, encryptor: *zencrypt.ZEncrypt, plaintext: []const u8) ![]u8 {
    var in_stream: std.Io.Reader = .fixed(plaintext);
    var out_buf: std.Io.Writer.Allocating = .init(allocator);
    defer out_buf.deinit();
    try encryptor.encrypt(&in_stream, &out_buf.writer);

    return allocator.dupe(u8, out_buf.written());
}

fn decryptPayload(allocator: std.mem.Allocator, decryptor: *zencrypt.ZEncrypt, ciphertext: []const u8) ![]u8 {
    var in_stream: std.Io.Reader = .fixed(ciphertext);
    var out_buf: std.Io.Writer.Allocating = .init(allocator);
    defer out_buf.deinit();
    try decryptor.decrypt(&in_stream, &out_buf.writer);

    return allocator.dupe(u8, out_buf.written());
}

fn scaledPayloadSize(base_size: usize, scale: u32) !usize {
    const factor: usize = @max(@as(usize, 1), @as(usize, scale));
    return std.math.mul(usize, base_size, factor);
}

fn maxBasePayloadSize() usize {
    var max_size: usize = 0;

    inline for (perf_workload_table) |workload| {
        if (workload.base_size > max_size) max_size = workload.base_size;
    }
    inline for (reliability_workload_table) |workload| {
        if (workload.base_size > max_size) max_size = workload.base_size;
    }

    return max_size;
}

fn workerSeed(worker_id: usize) u64 {
    const x = @as(u64, @intCast(worker_id + 1));
    return 0x9E3779B97F4A7C15 ^ (x *% 0xBF58476D1CE4E5B9);
}

fn algorithmIndex(algorithm: zencrypt.ZEncryptType) usize {
    return switch (algorithm) {
        .aes => 0,
        .xchacha20 => 1,
    };
}

fn algorithmLabel(algorithm: zencrypt.ZEncryptType) []const u8 {
    return switch (algorithm) {
        .aes => "aes",
        .xchacha20 => "xchacha20",
    };
}

fn printSummary(
    shared: *const SharedState,
    elapsed_ns: i128,
    perf_duration_ns: i128,
    reliability_duration_ns: i128,
    stress_seconds: u32,
    worker_count: usize,
    stress_scale: u32,
) Summary {
    const elapsed_seconds = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(NS_PER_S_I128));
    const perf_seconds = if (perf_duration_ns > 0)
        @as(f64, @floatFromInt(perf_duration_ns)) / @as(f64, @floatFromInt(NS_PER_S_I128))
    else
        0.0;
    const reliability_seconds = if (reliability_duration_ns > 0)
        @as(f64, @floatFromInt(reliability_duration_ns)) / @as(f64, @floatFromInt(NS_PER_S_I128))
    else
        0.0;

    var perf_roundtrips: u64 = 0;
    var perf_bytes: u64 = 0;
    var reliability_roundtrips: u64 = 0;
    var reliability_tamper_checks: u64 = 0;
    var reliability_bytes: u64 = 0;

    for (shared.perf_metrics) |m| {
        perf_roundtrips += m.roundtrip_ops;
        perf_bytes += m.bytes_processed;
    }
    for (shared.reliability_metrics) |m| {
        reliability_roundtrips += m.roundtrip_ops;
        reliability_tamper_checks += m.tamper_checks;
        reliability_bytes += m.bytes_processed;
    }

    const perf_throughput_mib_s = if (perf_seconds > 0)
        (@as(f64, @floatFromInt(perf_bytes)) / (1024.0 * 1024.0)) / perf_seconds
    else
        0.0;
    const reliability_throughput_mib_s = if (reliability_seconds > 0)
        (@as(f64, @floatFromInt(reliability_bytes)) / (1024.0 * 1024.0)) / reliability_seconds
    else
        0.0;

    std.debug.print(
        \\stress summary: workers={d} target_seconds={d} scale={d} elapsed={d:.2}s
        \\
    , .{ worker_count, stress_seconds, stress_scale, elapsed_seconds });
    std.debug.print(
        "performance phase: roundtrips={d} bytes={d} throughput={d:.2} MiB/s threshold={d:.2} MiB/s\n",
        .{
            perf_roundtrips,
            perf_bytes,
            perf_throughput_mib_s,
            stress_options.stress_min_throughput_mib,
        },
    );
    std.debug.print(
        "reliability phase: roundtrips={d} tamper_checks={d} bytes={d} throughput={d:.2} MiB/s failures={d}\n",
        .{
            reliability_roundtrips,
            reliability_tamper_checks,
            reliability_bytes,
            reliability_throughput_mib_s,
            shared.failures,
        },
    );

    const algorithms = [_]zencrypt.ZEncryptType{ .aes, .xchacha20 };
    for (algorithms) |algorithm| {
        const idx = algorithmIndex(algorithm);
        const perf = shared.perf_metrics[idx];
        const reliability = shared.reliability_metrics[idx];

        std.debug.print(
            "{s}: perf_roundtrips={d} perf_bytes={d} reliability_roundtrips={d} tamper_checks={d} reliability_bytes={d}\n",
            .{
                algorithmLabel(algorithm),
                perf.roundtrip_ops,
                perf.bytes_processed,
                reliability.roundtrip_ops,
                reliability.tamper_checks,
                reliability.bytes_processed,
            },
        );
    }

    if (shared.first_failure) |first| {
        std.debug.print(
            "first failure: worker={d} algorithm={s} workload={s} stage={s} err={}\n",
            .{ first.worker_id, algorithmLabel(first.algorithm), first.workload_name, first.stage, first.err },
        );
    }

    return .{
        .elapsed_seconds = elapsed_seconds,
        .perf_throughput_mib_s = perf_throughput_mib_s,
        .reliability_throughput_mib_s = reliability_throughput_mib_s,
    };
}
