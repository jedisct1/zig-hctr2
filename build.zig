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

    // Add test step
    const test_step = b.step("test", "Run unit tests");

    // HCTR3 tests
    const hctr3_test_mod = b.createModule(.{
        .root_source_file = b.path("src/hctr3_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const hctr3_tests = b.addTest(.{
        .name = "hctr3_test",
        .root_module = hctr3_test_mod,
    });
    const run_hctr3_tests = b.addRunArtifact(hctr3_tests);
    test_step.dependOn(&run_hctr3_tests.step);

    // Root module tests (if any)
    const root_test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const root_tests = b.addTest(.{
        .name = "root_test",
        .root_module = root_test_mod,
    });
    const run_root_tests = b.addRunArtifact(root_tests);
    test_step.dependOn(&run_root_tests.step);

    // HCTR2 tests (if any)
    const hctr2_test_mod = b.createModule(.{
        .root_source_file = b.path("src/hctr2.zig"),
        .target = target,
        .optimize = optimize,
    });
    const hctr2_tests = b.addTest(.{
        .name = "hctr2_test",
        .root_module = hctr2_test_mod,
    });
    const run_hctr2_tests = b.addRunArtifact(hctr2_tests);
    test_step.dependOn(&run_hctr2_tests.step);

    // LFSR tests
    const lfsr_test_mod = b.createModule(.{
        .root_source_file = b.path("src/lfsr_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lfsr_tests = b.addTest(.{
        .name = "lfsr_test",
        .root_module = lfsr_test_mod,
    });
    const run_lfsr_tests = b.addRunArtifact(lfsr_tests);
    test_step.dependOn(&run_lfsr_tests.step);

    // Add benchmark step
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

    // Install the benchmark binary
    const install_benchmark = b.addInstallArtifact(benchmark_exe, .{});
    b.getInstallStep().dependOn(&install_benchmark.step);
}
