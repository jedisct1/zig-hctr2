const std = @import("std");
const hctr2 = @import("hctr2.zig");
const hctr3 = @import("hctr3.zig");

const Timer = std.time.Timer;
const print = std.debug.print;

const message_sizes = [_]usize{ 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576 };
const message_size_names = [_][]const u8{ "16B", "64B", "256B", "1KB", "4KB", "16KB", "64KB", "256KB", "1MB" };

fn benchmarkHCTR2_128(allocator: std.mem.Allocator) !void {
    print("\n=== HCTR2 AES-128 Benchmarks ===\n", .{});

    const key = [_]u8{0x00} ** 16;
    const tweak = [_]u8{0x00} ** 16;

    var timer = try Timer.start();

    // Benchmark initialization
    const start_init = timer.read();
    var cipher = hctr2.Hctr2_128.init(key);
    const init_time = timer.read() - start_init;
    print("Initialization: {d:.3} µs\n\n", .{@as(f64, @floatFromInt(init_time)) / 1000.0});

    print("{s:>10} | {s:>12} | {s:>12} | {s:>12} | {s:>12}\n", .{ "Size", "Encrypt (µs)", "Decrypt (µs)", "Enc MB/s", "Dec MB/s" });
    print("{s:->10}-+-{s:->12}-+-{s:->12}-+-{s:->12}-+-{s:->12}\n", .{ "", "", "", "", "" });

    for (message_sizes, message_size_names) |size, name| {
        const message = try allocator.alloc(u8, size);
        defer allocator.free(message);
        const ciphertext = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext);
        const plaintext = try allocator.alloc(u8, size);
        defer allocator.free(plaintext);

        // Fill with test data
        for (message) |*b| {
            b.* = 0x42;
        }

        // Warmup
        try cipher.encrypt(ciphertext, message, &tweak);
        try cipher.decrypt(plaintext, ciphertext, &tweak);

        // Benchmark encryption
        const iterations: usize = if (size < 1024) 10000 else if (size < 65536) 1000 else 100;

        const start_enc = timer.read();
        for (0..iterations) |_| {
            try cipher.encrypt(ciphertext, message, &tweak);
        }
        const enc_time = timer.read() - start_enc;
        const enc_time_per_op = @as(f64, @floatFromInt(enc_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

        // Benchmark decryption
        const start_dec = timer.read();
        for (0..iterations) |_| {
            try cipher.decrypt(plaintext, ciphertext, &tweak);
        }
        const dec_time = timer.read() - start_dec;
        const dec_time_per_op = @as(f64, @floatFromInt(dec_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

        // Calculate throughput in MB/s
        const enc_mbps = (@as(f64, @floatFromInt(size)) / 1048576.0) / (enc_time_per_op / 1000000.0);
        const dec_mbps = (@as(f64, @floatFromInt(size)) / 1048576.0) / (dec_time_per_op / 1000000.0);

        print("{s:>10} | {d:>12.3} | {d:>12.3} | {d:>12.1} | {d:>12.1}\n", .{
            name,
            enc_time_per_op,
            dec_time_per_op,
            enc_mbps,
            dec_mbps,
        });
    }
}

fn benchmarkHCTR2_256(allocator: std.mem.Allocator) !void {
    print("\n=== HCTR2 AES-256 Benchmarks ===\n", .{});

    const key = [_]u8{0x00} ** 32;
    const tweak = [_]u8{0x00} ** 16;

    var timer = try Timer.start();

    // Benchmark initialization
    const start_init = timer.read();
    var cipher = hctr2.Hctr2_256.init(key);
    const init_time = timer.read() - start_init;
    print("Initialization: {d:.3} µs\n\n", .{@as(f64, @floatFromInt(init_time)) / 1000.0});

    print("{s:>10} | {s:>12} | {s:>12} | {s:>12} | {s:>12}\n", .{ "Size", "Encrypt (µs)", "Decrypt (µs)", "Enc MB/s", "Dec MB/s" });
    print("{s:->10}-+-{s:->12}-+-{s:->12}-+-{s:->12}-+-{s:->12}\n", .{ "", "", "", "", "" });

    for (message_sizes, message_size_names) |size, name| {
        const message = try allocator.alloc(u8, size);
        defer allocator.free(message);
        const ciphertext = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext);
        const plaintext = try allocator.alloc(u8, size);
        defer allocator.free(plaintext);

        // Fill with test data
        for (message) |*b| {
            b.* = 0x42;
        }

        // Warmup
        try cipher.encrypt(ciphertext, message, &tweak);
        try cipher.decrypt(plaintext, ciphertext, &tweak);

        // Benchmark encryption
        const iterations: usize = if (size < 1024) 10000 else if (size < 65536) 1000 else 100;

        const start_enc = timer.read();
        for (0..iterations) |_| {
            try cipher.encrypt(ciphertext, message, &tweak);
        }
        const enc_time = timer.read() - start_enc;
        const enc_time_per_op = @as(f64, @floatFromInt(enc_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

        // Benchmark decryption
        const start_dec = timer.read();
        for (0..iterations) |_| {
            try cipher.decrypt(plaintext, ciphertext, &tweak);
        }
        const dec_time = timer.read() - start_dec;
        const dec_time_per_op = @as(f64, @floatFromInt(dec_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

        // Calculate throughput in MB/s
        const enc_mbps = (@as(f64, @floatFromInt(size)) / 1048576.0) / (enc_time_per_op / 1000000.0);
        const dec_mbps = (@as(f64, @floatFromInt(size)) / 1048576.0) / (dec_time_per_op / 1000000.0);

        print("{s:>10} | {d:>12.3} | {d:>12.3} | {d:>12.1} | {d:>12.1}\n", .{
            name,
            enc_time_per_op,
            dec_time_per_op,
            enc_mbps,
            dec_mbps,
        });
    }
}

fn benchmarkHCTR3_128(allocator: std.mem.Allocator) !void {
    print("\n=== HCTR3 AES-128 Benchmarks ===\n", .{});

    const key = [_]u8{0x00} ** 16;
    const tweak = [_]u8{0x00} ** 16;

    var timer = try Timer.start();

    // Benchmark initialization
    const start_init = timer.read();
    var cipher = hctr3.Hctr3_128.init(key);
    const init_time = timer.read() - start_init;
    print("Initialization: {d:.3} µs\n\n", .{@as(f64, @floatFromInt(init_time)) / 1000.0});

    print("{s:>10} | {s:>12} | {s:>12} | {s:>12} | {s:>12}\n", .{ "Size", "Encrypt (µs)", "Decrypt (µs)", "Enc MB/s", "Dec MB/s" });
    print("{s:->10}-+-{s:->12}-+-{s:->12}-+-{s:->12}-+-{s:->12}\n", .{ "", "", "", "", "" });

    for (message_sizes, message_size_names) |size, name| {
        const message = try allocator.alloc(u8, size);
        defer allocator.free(message);
        const ciphertext = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext);
        const plaintext = try allocator.alloc(u8, size);
        defer allocator.free(plaintext);

        // Fill with test data
        for (message) |*b| {
            b.* = 0x42;
        }

        // Warmup
        try cipher.encrypt(ciphertext, message, &tweak);
        try cipher.decrypt(plaintext, ciphertext, &tweak);

        // Benchmark encryption
        const iterations: usize = if (size < 1024) 10000 else if (size < 65536) 1000 else 100;

        const start_enc = timer.read();
        for (0..iterations) |_| {
            try cipher.encrypt(ciphertext, message, &tweak);
        }
        const enc_time = timer.read() - start_enc;
        const enc_time_per_op = @as(f64, @floatFromInt(enc_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

        // Benchmark decryption
        const start_dec = timer.read();
        for (0..iterations) |_| {
            try cipher.decrypt(plaintext, ciphertext, &tweak);
        }
        const dec_time = timer.read() - start_dec;
        const dec_time_per_op = @as(f64, @floatFromInt(dec_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

        // Calculate throughput in MB/s
        const enc_mbps = (@as(f64, @floatFromInt(size)) / 1048576.0) / (enc_time_per_op / 1000000.0);
        const dec_mbps = (@as(f64, @floatFromInt(size)) / 1048576.0) / (dec_time_per_op / 1000000.0);

        print("{s:>10} | {d:>12.3} | {d:>12.3} | {d:>12.1} | {d:>12.1}\n", .{
            name,
            enc_time_per_op,
            dec_time_per_op,
            enc_mbps,
            dec_mbps,
        });
    }
}

fn benchmarkHCTR3_256(allocator: std.mem.Allocator) !void {
    print("\n=== HCTR3 AES-256 Benchmarks ===\n", .{});

    const key = [_]u8{0x00} ** 32;
    const tweak = [_]u8{0x00} ** 16;

    var timer = try Timer.start();

    // Benchmark initialization
    const start_init = timer.read();
    var cipher = hctr3.Hctr3_256.init(key);
    const init_time = timer.read() - start_init;
    print("Initialization: {d:.3} µs\n\n", .{@as(f64, @floatFromInt(init_time)) / 1000.0});

    print("{s:>10} | {s:>12} | {s:>12} | {s:>12} | {s:>12}\n", .{ "Size", "Encrypt (µs)", "Decrypt (µs)", "Enc MB/s", "Dec MB/s" });
    print("{s:->10}-+-{s:->12}-+-{s:->12}-+-{s:->12}-+-{s:->12}\n", .{ "", "", "", "", "" });

    for (message_sizes, message_size_names) |size, name| {
        const message = try allocator.alloc(u8, size);
        defer allocator.free(message);
        const ciphertext = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext);
        const plaintext = try allocator.alloc(u8, size);
        defer allocator.free(plaintext);

        // Fill with test data
        for (message) |*b| {
            b.* = 0x42;
        }

        // Warmup
        try cipher.encrypt(ciphertext, message, &tweak);
        try cipher.decrypt(plaintext, ciphertext, &tweak);

        // Benchmark encryption
        const iterations: usize = if (size < 1024) 10000 else if (size < 65536) 1000 else 100;

        const start_enc = timer.read();
        for (0..iterations) |_| {
            try cipher.encrypt(ciphertext, message, &tweak);
        }
        const enc_time = timer.read() - start_enc;
        const enc_time_per_op = @as(f64, @floatFromInt(enc_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

        // Benchmark decryption
        const start_dec = timer.read();
        for (0..iterations) |_| {
            try cipher.decrypt(plaintext, ciphertext, &tweak);
        }
        const dec_time = timer.read() - start_dec;
        const dec_time_per_op = @as(f64, @floatFromInt(dec_time)) / @as(f64, @floatFromInt(iterations)) / 1000.0;

        // Calculate throughput in MB/s
        const enc_mbps = (@as(f64, @floatFromInt(size)) / 1048576.0) / (enc_time_per_op / 1000000.0);
        const dec_mbps = (@as(f64, @floatFromInt(size)) / 1048576.0) / (dec_time_per_op / 1000000.0);

        print("{s:>10} | {d:>12.3} | {d:>12.3} | {d:>12.1} | {d:>12.1}\n", .{
            name,
            enc_time_per_op,
            dec_time_per_op,
            enc_mbps,
            dec_mbps,
        });
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("HCTR2/HCTR3 Cryptographic Mode Benchmarks\n", .{});
    print("==========================================\n", .{});

    try benchmarkHCTR2_128(allocator);
    try benchmarkHCTR2_256(allocator);
    try benchmarkHCTR3_128(allocator);
    try benchmarkHCTR3_256(allocator);

    print("\n", .{});
}
