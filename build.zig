const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("hctr2", .{
        .root_source_file = b.path("src/root.zig"),
    });

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "hctr2",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    const test_step = b.step("test", "Run unit tests");
    const test_files = [_][]const u8{
        "src/root.zig",
        "src/hctr2.zig",
        "src/chctr2.zig",
        "src/hctr2_twkd.zig",
        "src/hctr2pp.zig",
        "src/hctr3_test.zig",
        "src/hctr2fp_test.zig",
        "src/hctr3fp_test.zig",
        "src/lfsr_test.zig",
    };
    for (test_files) |path| {
        const test_mod = b.createModule(.{
            .root_source_file = b.path(path),
            .target = target,
            .optimize = optimize,
        });
        const tests = b.addTest(.{
            .name = std.fs.path.stem(path),
            .root_module = test_mod,
        });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }

    const benchmark_step = b.step("bench", "Run benchmarks");

    const benchmark_mod = b.createModule(.{
        .root_source_file = b.path("src/benchmark.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    const benchmark_exe = b.addExecutable(.{
        .name = "benchmark",
        .root_module = benchmark_mod,
    });
    const run_benchmark = b.addRunArtifact(benchmark_exe);
    benchmark_step.dependOn(&run_benchmark.step);

    const install_benchmark = b.addInstallArtifact(benchmark_exe, .{});
    b.getInstallStep().dependOn(&install_benchmark.step);
}
