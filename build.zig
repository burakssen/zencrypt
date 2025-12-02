const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("zencrypt", .{
        .root_source_file = b.path("src/zencrypt.zig"),
        .target = target,
    });

    const examples_exe = b.addExecutable(.{
        .name = "zencrypt",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zencrypt", .module = mod },
            },
        }),
    });

    b.installArtifact(examples_exe);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(examples_exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const example_exe_tests = b.addTest(.{
        .root_module = examples_exe.root_module,
    });

    const run_example_exe_tests = b.addRunArtifact(example_exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_example_exe_tests.step);
}
