const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const stress_seconds = b.option(u32, "stress-seconds", "Stress test duration in seconds") orelse 75;
    const stress_workers = b.option(u32, "stress-workers", "Number of worker threads for stress tests") orelse 4;
    const stress_scale = b.option(u32, "stress-scale", "Workload scaling factor for stress tests") orelse 1;
    const stress_min_throughput_mib = b.option(f64, "stress-min-throughput-mib", "Minimum required performance phase throughput in MiB/s") orelse 20.0;

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/zencrypt.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "zencrypt",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    const example_mod = b.createModule(.{
        .root_source_file = b.path("examples/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zencrypt", .module = lib_mod },
        },
    });

    const example = b.addExecutable(.{
        .name = "zencrypt-example",
        .root_module = example_mod,
    });

    b.installArtifact(example);

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const example_run = b.addRunArtifact(example);

    if (b.args) |args| {
        example_run.addArgs(args);
    }

    const example_step = b.step("example", "Run example");
    example_step.dependOn(&example_run.step);

    const stress_release_opts = b.addOptions();
    stress_release_opts.addOption(u32, "stress_seconds", stress_seconds);
    stress_release_opts.addOption(u32, "stress_workers", stress_workers);
    stress_release_opts.addOption(u32, "stress_scale", stress_scale);
    stress_release_opts.addOption(f64, "stress_min_throughput_mib", stress_min_throughput_mib);
    stress_release_opts.addOption(bool, "stress_enforce_throughput_gate", true);

    const stress_release_lib_mod = b.createModule(.{
        .root_source_file = b.path("src/zencrypt.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });

    const stress_release_mod = b.createModule(.{
        .root_source_file = b.path("testing/stress.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{
            .{ .name = "zencrypt", .module = stress_release_lib_mod },
            .{ .name = "stress_options", .module = stress_release_opts.createModule() },
        },
    });

    const stress_release = b.addExecutable(.{
        .name = "zencrypt-stress",
        .root_module = stress_release_mod,
    });

    const stress_release_run = b.addRunArtifact(stress_release);
    const stress_step = b.step("stress", "Run stress tests (ReleaseFast with throughput gate)");
    stress_step.dependOn(&stress_release_run.step);

    const stress_debug_opts = b.addOptions();
    stress_debug_opts.addOption(u32, "stress_seconds", stress_seconds);
    stress_debug_opts.addOption(u32, "stress_workers", stress_workers);
    stress_debug_opts.addOption(u32, "stress_scale", stress_scale);
    stress_debug_opts.addOption(f64, "stress_min_throughput_mib", stress_min_throughput_mib);
    stress_debug_opts.addOption(bool, "stress_enforce_throughput_gate", false);

    const stress_debug_lib_mod = b.createModule(.{
        .root_source_file = b.path("src/zencrypt.zig"),
        .target = target,
        .optimize = .Debug,
    });

    const stress_debug_mod = b.createModule(.{
        .root_source_file = b.path("src/stress.zig"),
        .target = target,
        .optimize = .Debug,
        .imports = &.{
            .{ .name = "zencrypt", .module = stress_debug_lib_mod },
            .{ .name = "stress_options", .module = stress_debug_opts.createModule() },
        },
    });

    const stress_debug = b.addExecutable(.{
        .name = "zencrypt-stress-debug",
        .root_module = stress_debug_mod,
    });

    const stress_debug_run = b.addRunArtifact(stress_debug);
    const stress_debug_step = b.step("stress-debug", "Run stress tests (Debug reliability mode)");
    stress_debug_step.dependOn(&stress_debug_run.step);
}
