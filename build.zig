const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
}
