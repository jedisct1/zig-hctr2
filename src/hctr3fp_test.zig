const std = @import("std");
const testing = std.testing;
const hctr3fp = @import("hctr3fp.zig");
const aes = std.crypto.core.aes;

// Test helper: verify first block length calculations
test "HCTR3-FP computeFirstBlockLength" {
    // Special case: radix=256 should be 16 (same as standard HCTR3)
    const Hctr3Fp_256 = hctr3fp.Hctr3Fp(aes.Aes128, std.crypto.hash.sha2.Sha256, 256);
    try testing.expectEqual(16, Hctr3Fp_256.first_block_length);

    // Common radixes
    const Hctr3Fp_10 = hctr3fp.Hctr3Fp(aes.Aes128, std.crypto.hash.sha2.Sha256, 10);
    try testing.expectEqual(39, Hctr3Fp_10.first_block_length); // ceil(128 / log2(10)) = 39

    const Hctr3Fp_16 = hctr3fp.Hctr3Fp(aes.Aes128, std.crypto.hash.sha2.Sha256, 16);
    try testing.expectEqual(32, Hctr3Fp_16.first_block_length); // 128 / 4 = 32

    const Hctr3Fp_64 = hctr3fp.Hctr3Fp(aes.Aes128, std.crypto.hash.sha2.Sha256, 64);
    try testing.expectEqual(22, Hctr3Fp_64.first_block_length); // ceil(128 / 6) = 22
}

// Test base conversion round-trip for various radixes
test "HCTR3-FP base conversion round-trip - radix 10" {
    const Cipher = hctr3fp.Hctr3Fp(aes.Aes128, std.crypto.hash.sha2.Sha256, 10);
    const radix = 10;
    const first_len = Cipher.first_block_length;

    var buffer: [first_len]u8 = undefined;

    // Test zero
    {
        const value: u128 = 0;
        hctr3fp.encodeBaseRadix(value, radix, &buffer);
        for (buffer) |d| {
            try testing.expect(d < radix);
        }
        const decoded = try hctr3fp.decodeBaseRadix(&buffer, radix);
        try testing.expectEqual(value, decoded);
    }

    // Test max u128
    {
        const value: u128 = std.math.maxInt(u128);
        hctr3fp.encodeBaseRadix(value, radix, &buffer);
        for (buffer) |d| {
            try testing.expect(d < radix);
        }
        const decoded = try hctr3fp.decodeBaseRadix(&buffer, radix);
        try testing.expectEqual(value, decoded);
    }
}

// Test LFSR next state function
test "HCTR3-FP LFSR next state - 128-bit" {
    const Cipher = hctr3fp.Hctr3Fp_128_Decimal;

    // Test that LFSR produces different states
    var state: [16]u8 = @splat(1);
    const state2 = Cipher.lfsr_next(state);
    const state3 = Cipher.lfsr_next(state2);

    // States should all be different
    try testing.expect(!std.mem.eql(u8, &state, &state2));
    try testing.expect(!std.mem.eql(u8, &state2, &state3));
    try testing.expect(!std.mem.eql(u8, &state, &state3));

    // Test all-zero state (should produce non-zero)
    const zero_state: [16]u8 = @splat(0);
    const next_zero = Cipher.lfsr_next(zero_state);
    try testing.expectEqualSlices(u8, &zero_state, &next_zero); // LFSR with all-zero input stays zero
}

test "HCTR3-FP LFSR next state - AES-256" {
    const Cipher = hctr3fp.Hctr3Fp_256_Decimal;

    // Note: AES-256 still has a 16-byte block size (256 refers to key size)
    // Test that LFSR produces different states
    var state: [16]u8 = @splat(1);
    const state2 = Cipher.lfsr_next(state);
    const state3 = Cipher.lfsr_next(state2);

    // States should all be different
    try testing.expect(!std.mem.eql(u8, &state, &state2));
    try testing.expect(!std.mem.eql(u8, &state2, &state3));
    try testing.expect(!std.mem.eql(u8, &state, &state3));
}

// Encryption/decryption round-trip tests
test "HCTR3-FP encrypt/decrypt round-trip - radix 10, minimum length" {
    const Cipher = hctr3fp.Hctr3Fp_128_Decimal;
    const key: [16]u8 = @splat(0x42);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    // Create plaintext by encoding a valid u128 value
    var plaintext: [first_len]u8 = undefined;
    const value: u128 = 0x0123456789ABCDEF_FEDCBA9876543210;
    hctr3fp.encodeBaseRadix(value, 10, &plaintext);

    var ciphertext: [first_len]u8 = undefined;
    var decrypted: [first_len]u8 = undefined;
    const tweak = "test_tweak";

    try cipher.encrypt(&ciphertext, &plaintext, tweak);

    // Verify all ciphertext digits are valid
    for (ciphertext) |c| {
        try testing.expect(c < 10);
    }

    try cipher.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR3-FP encrypt/decrypt round-trip - radix 10, with tail" {
    const Cipher = hctr3fp.Hctr3Fp_128_Decimal;
    const key: [16]u8 = @splat(0x99);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    const tail_len = 61;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    // Encode first block from a valid u128
    const value: u128 = 0xDEADBEEFCAFEBABE_123456789ABCDEF0;
    hctr3fp.encodeBaseRadix(value, 10, plaintext[0..first_len]);

    // Fill tail with valid digits
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast((i * 7) % 10);
    }

    var ciphertext: [message_len]u8 = undefined;
    var decrypted: [message_len]u8 = undefined;
    const tweak = "user_id_12345";

    try cipher.encrypt(&ciphertext, &plaintext, tweak);

    // Verify all ciphertext digits are valid
    for (ciphertext) |c| {
        try testing.expect(c < 10);
    }

    // Ciphertext should differ from plaintext
    try testing.expect(!std.mem.eql(u8, &plaintext, &ciphertext));

    try cipher.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR3-FP encrypt/decrypt round-trip - radix 16" {
    const Cipher = hctr3fp.Hctr3Fp_128_Hex;
    const key: [16]u8 = @splat(0x11);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    const tail_len = 32;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    // Encode first block
    hctr3fp.encodeBaseRadix(0xFEDCBA9876543210_0123456789ABCDEF, 16, plaintext[0..first_len]);

    // Fill tail
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast(i % 16);
    }

    var ciphertext: [message_len]u8 = undefined;
    var decrypted: [message_len]u8 = undefined;

    try cipher.encrypt(&ciphertext, &plaintext, "");

    for (ciphertext) |c| {
        try testing.expect(c < 16);
    }

    try cipher.decrypt(&decrypted, &ciphertext, "");

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR3-FP encrypt/decrypt round-trip - radix 64" {
    const Cipher = hctr3fp.Hctr3Fp_128_Base64;
    const key: [16]u8 = @splat(0xAA);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    const tail_len = 28;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    // Encode first block
    hctr3fp.encodeBaseRadix(0xABCDEF0123456789_FEDCBA9876543210, 64, plaintext[0..first_len]);

    // Fill tail
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast((i * 13) % 64);
    }

    var ciphertext: [message_len]u8 = undefined;
    var decrypted: [message_len]u8 = undefined;
    const tweak = "some_context";

    try cipher.encrypt(&ciphertext, &plaintext, tweak);

    for (ciphertext) |c| {
        try testing.expect(c < 64);
    }

    try cipher.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR3-FP AES-256 variant - radix 10" {
    const Cipher = hctr3fp.Hctr3Fp_256_Decimal;
    const key: [32]u8 = @splat(0x33);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    const tail_len = 50;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    // Encode first block
    hctr3fp.encodeBaseRadix(0x123456789ABCDEF0_FEDCBA9876543210, 10, plaintext[0..first_len]);

    // Fill tail
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast((i * 3) % 10);
    }

    var ciphertext: [message_len]u8 = undefined;
    var decrypted: [message_len]u8 = undefined;
    const tweak = "aes256_test";

    try cipher.encrypt(&ciphertext, &plaintext, tweak);

    for (ciphertext) |c| {
        try testing.expect(c < 10);
    }

    try cipher.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR3-FP different tweaks produce different ciphertexts" {
    const Cipher = hctr3fp.Hctr3Fp_128_Decimal;
    const key: [16]u8 = @splat(0x55);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    const tail_len = 11;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    // Encode first block
    hctr3fp.encodeBaseRadix(123456789, 10, plaintext[0..first_len]);

    // Fill tail
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast(i % 10);
    }

    var ciphertext1: [message_len]u8 = undefined;
    var ciphertext2: [message_len]u8 = undefined;

    try cipher.encrypt(&ciphertext1, &plaintext, "tweak1");
    try cipher.encrypt(&ciphertext2, &plaintext, "tweak2");

    // Different tweaks should produce different ciphertexts
    try testing.expect(!std.mem.eql(u8, &ciphertext1, &ciphertext2));
}

test "HCTR3-FP different keys produce different ciphertexts" {
    const Cipher = hctr3fp.Hctr3Fp_128_Decimal;

    const key1: [16]u8 = @splat(0x01);
    const key2: [16]u8 = @splat(0x02);
    var cipher1 = Cipher.init(key1);
    var cipher2 = Cipher.init(key2);

    const first_len = Cipher.first_block_length;
    const tail_len = 11;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    // Encode first block
    hctr3fp.encodeBaseRadix(987654321, 10, plaintext[0..first_len]);

    // Fill tail
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast(i % 10);
    }

    var ciphertext1: [message_len]u8 = undefined;
    var ciphertext2: [message_len]u8 = undefined;
    const tweak = "same_tweak";

    try cipher1.encrypt(&ciphertext1, &plaintext, tweak);
    try cipher2.encrypt(&ciphertext2, &plaintext, tweak);

    // Different keys should produce different ciphertexts
    try testing.expect(!std.mem.eql(u8, &ciphertext1, &ciphertext2));
}

test "HCTR3-FP long tweak handling" {
    const Cipher = hctr3fp.Hctr3Fp_128_Hex;
    const key: [16]u8 = @splat(0xBB);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    const tail_len = 20;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    hctr3fp.encodeBaseRadix(0xABCDEF0123456789, 16, plaintext[0..first_len]);
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast(i % 16);
    }

    var ciphertext1: [message_len]u8 = undefined;
    var ciphertext2: [message_len]u8 = undefined;
    var decrypted: [message_len]u8 = undefined;

    // Test with a very long tweak (longer than SHA-256 block size)
    const long_tweak = "This is a very long tweak that exceeds the SHA-256 block size of 64 bytes. " ++
        "It should be handled correctly by the SHA-256 hashing mechanism in HCTR3. " ++
        "The purpose of this test is to ensure that long tweaks are properly processed.";

    try cipher.encrypt(&ciphertext1, &plaintext, long_tweak);

    // Should decrypt correctly
    try cipher.decrypt(&decrypted, &ciphertext1, long_tweak);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    // Different long tweak should produce different ciphertext
    const different_long_tweak = "This is a different very long tweak that also exceeds the SHA-256 block size. " ++
        "It should produce a completely different ciphertext even though it's similar in length. " ++
        "This verifies that the SHA-256 hashing properly differentiates between tweaks.";

    try cipher.encrypt(&ciphertext2, &plaintext, different_long_tweak);
    try testing.expect(!std.mem.eql(u8, &ciphertext1, &ciphertext2));
}

test "HCTR3-FP error on input too short" {
    const Cipher = hctr3fp.Hctr3Fp_128_Decimal;
    const key: [16]u8 = @splat(0x42);
    var cipher = Cipher.init(key);

    const short_message = [_]u8{ 1, 2, 3, 4, 5 }; // Much shorter than first_block_length
    var output: [5]u8 = undefined;

    const result = cipher.encrypt(&output, &short_message, "");
    try testing.expectError(error.InputTooShort, result);
}

test "HCTR3-FP error on invalid digit in input" {
    const Cipher = hctr3fp.Hctr3Fp_128_Decimal;
    const key: [16]u8 = @splat(0x42);
    var cipher = Cipher.init(key);

    var plaintext: [50]u8 = undefined;
    for (&plaintext, 0..) |*p, i| {
        p.* = @intCast(i % 10);
    }
    plaintext[25] = 10; // Invalid digit for radix 10

    var ciphertext: [50]u8 = undefined;

    const result = cipher.encrypt(&ciphertext, &plaintext, "");
    try testing.expectError(error.InvalidDigit, result);
}

test "HCTR3-FP various message lengths - radix 10" {
    const Cipher = hctr3fp.Hctr3Fp_128_Decimal;
    const key: [16]u8 = @splat(0x77);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    const test_lengths = [_]usize{ 39, 40, 50, 64, 100, 127, 128, 129, 200 };

    for (test_lengths) |len| {
        const plaintext = try testing.allocator.alloc(u8, len);
        defer testing.allocator.free(plaintext);

        // Encode first block
        const value: u128 = 0x0123456789ABCDEF_FEDCBA9876543210;
        hctr3fp.encodeBaseRadix(value, 10, plaintext[0..first_len]);

        // Fill tail (if any)
        if (len > first_len) {
            for (plaintext[first_len..], 0..) |*p, i| {
                p.* = @intCast((i * 3) % 10);
            }
        }

        const ciphertext = try testing.allocator.alloc(u8, len);
        defer testing.allocator.free(ciphertext);

        const decrypted = try testing.allocator.alloc(u8, len);
        defer testing.allocator.free(decrypted);

        try cipher.encrypt(ciphertext, plaintext, "length_test");

        for (ciphertext) |c| {
            try testing.expect(c < 10);
        }

        try cipher.decrypt(decrypted, ciphertext, "length_test");

        try testing.expectEqualSlices(u8, plaintext, decrypted);
    }
}

test "HCTR3-FP deterministic test vector - radix 10" {
    const Cipher = hctr3fp.Hctr3Fp_128_Decimal;
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    const tail_len = 11;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    // Encode first block
    hctr3fp.encodeBaseRadix(0x0123456789ABCDEF_0123456789ABCDEF, 10, plaintext[0..first_len]);

    // Fill tail with pattern
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast(i % 10);
    }

    var ciphertext: [message_len]u8 = undefined;
    const tweak = "test_vector_001";

    try cipher.encrypt(&ciphertext, &plaintext, tweak);

    // Encrypt again to verify determinism
    var ciphertext2: [message_len]u8 = undefined;
    try cipher.encrypt(&ciphertext2, &plaintext, tweak);

    try testing.expectEqualSlices(u8, &ciphertext, &ciphertext2);

    // Decrypt and verify
    var decrypted: [message_len]u8 = undefined;
    try cipher.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR3-FP partial block tail handling" {
    const Cipher = hctr3fp.Hctr3Fp_128_Hex;
    const key: [16]u8 = @splat(0xCC);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;

    // Test various tail lengths including partial AES blocks
    const tail_lengths = [_]usize{ 1, 7, 15, 16, 17, 31, 32, 33, 47, 48 };

    for (tail_lengths) |tail_len| {
        const message_len = first_len + tail_len;
        const plaintext = try testing.allocator.alloc(u8, message_len);
        defer testing.allocator.free(plaintext);

        hctr3fp.encodeBaseRadix(0x123456789ABCDEF0, 16, plaintext[0..first_len]);
        for (plaintext[first_len..], 0..) |*p, i| {
            p.* = @intCast(i % 16);
        }

        const ciphertext = try testing.allocator.alloc(u8, message_len);
        defer testing.allocator.free(ciphertext);

        const decrypted = try testing.allocator.alloc(u8, message_len);
        defer testing.allocator.free(decrypted);

        try cipher.encrypt(ciphertext, plaintext, "partial_block");

        for (ciphertext) |c| {
            try testing.expect(c < 16);
        }

        try cipher.decrypt(decrypted, ciphertext, "partial_block");

        try testing.expectEqualSlices(u8, plaintext, decrypted);
    }
}

// Test that HCTR3-FP produces different output than HCTR2-FP
// (This requires both implementations to be available - skip if hctr2fp not available)
test "HCTR3-FP vs HCTR2-FP difference" {
    const Hctr2Fp = @import("hctr2fp.zig").Hctr2Fp_128_Decimal;
    const Hctr3Fp = hctr3fp.Hctr3Fp_128_Decimal;

    const key: [16]u8 = @splat(0x88);
    var cipher2 = Hctr2Fp.init(key);
    var cipher3 = Hctr3Fp.init(key);

    const first_len = Hctr3Fp.first_block_length;
    const tail_len = 30;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    hctr3fp.encodeBaseRadix(0xABCDEF0123456789, 10, plaintext[0..first_len]);
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast(i % 10);
    }

    var ciphertext2: [message_len]u8 = undefined;
    var ciphertext3: [message_len]u8 = undefined;
    const tweak = "compare_test";

    try cipher2.encrypt(&ciphertext2, &plaintext, tweak);
    try cipher3.encrypt(&ciphertext3, &plaintext, tweak);

    // HCTR2-FP and HCTR3-FP should produce different ciphertexts
    try testing.expect(!std.mem.eql(u8, &ciphertext2, &ciphertext3));
}

// Test for radix 94 overflow issue
test "HCTR3-FP base conversion round-trip - radix 94" {
    const Cipher = hctr3fp.Hctr3Fp(aes.Aes128, std.crypto.hash.sha2.Sha256, 94);
    const radix = 94;
    const first_len = Cipher.first_block_length;

    var buffer: [first_len]u8 = undefined;

    // Test zero
    {
        const value: u128 = 0;
        hctr3fp.encodeBaseRadix(value, radix, &buffer);
        for (buffer) |d| {
            try testing.expect(d < radix);
        }
        const decoded = try hctr3fp.decodeBaseRadix(&buffer, radix);
        try testing.expectEqual(value, decoded);
    }

    // Test small value
    {
        const value: u128 = 12345;
        hctr3fp.encodeBaseRadix(value, radix, &buffer);
        for (buffer) |d| {
            try testing.expect(d < radix);
        }
        const decoded = try hctr3fp.decodeBaseRadix(&buffer, radix);
        try testing.expectEqual(value, decoded);
    }

    // Test large value
    {
        const value: u128 = 0xDEADBEEFCAFEBABE0123456789ABCDEF;
        hctr3fp.encodeBaseRadix(value, radix, &buffer);
        for (buffer) |d| {
            try testing.expect(d < radix);
        }
        const decoded = try hctr3fp.decodeBaseRadix(&buffer, radix);
        try testing.expectEqual(value, decoded);
    }

    // Test max u128 - this is where overflow occurs
    {
        const value: u128 = std.math.maxInt(u128);
        hctr3fp.encodeBaseRadix(value, radix, &buffer);
        for (buffer) |d| {
            try testing.expect(d < radix);
        }
        const decoded = try hctr3fp.decodeBaseRadix(&buffer, radix);
        try testing.expectEqual(value, decoded);
    }
}

// Test encryption/decryption with radix 94
test "HCTR3-FP encrypt/decrypt round-trip - radix 94" {
    const Cipher = hctr3fp.Hctr3Fp(aes.Aes128, std.crypto.hash.sha2.Sha256, 94);
    const key: [16]u8 = @splat(0x42);
    var cipher = Cipher.init(key);

    const first_len = Cipher.first_block_length;
    const tail_len = 30;
    const message_len = first_len + tail_len;
    var plaintext: [message_len]u8 = undefined;

    // Encode first block from a valid u128
    const value: u128 = std.math.maxInt(u128);
    hctr3fp.encodeBaseRadix(value, 94, plaintext[0..first_len]);

    // Fill tail with valid digits
    for (plaintext[first_len..], 0..) |*p, i| {
        p.* = @intCast((i * 7) % 94);
    }

    var ciphertext: [message_len]u8 = undefined;
    var decrypted: [message_len]u8 = undefined;
    const tweak = "test_radix_94";

    try cipher.encrypt(&ciphertext, &plaintext, tweak);

    // Verify all ciphertext digits are valid
    for (ciphertext) |c| {
        try testing.expect(c < 94);
    }

    try cipher.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

// Comprehensive test: various radices with various message sizes
test "HCTR3-FP encrypt/decrypt round-trip - various radices and message sizes" {
    // Test radices: 8, 10, 50, 96, 100, 150
    const test_radices = [_]u16{ 8, 10, 50, 96, 100, 150 };

    inline for (test_radices) |radix| {
        const Cipher = hctr3fp.Hctr3Fp(aes.Aes128, std.crypto.hash.sha2.Sha256, radix);
        const key: [16]u8 = @splat(@as(u8, @intCast(radix & 0xFF)));
        var cipher = Cipher.init(key);

        const first_len = Cipher.first_block_length;

        // Test various message sizes relative to first_block_length
        // We test: exact minimum, small tail, medium tail, large tail
        const tail_sizes = [_]usize{ 0, 10, 50, 100, 150 };

        for (tail_sizes) |tail_size| {
            const message_len = first_len + tail_size;

            const plaintext = try testing.allocator.alloc(u8, message_len);
            defer testing.allocator.free(plaintext);

            const ciphertext = try testing.allocator.alloc(u8, message_len);
            defer testing.allocator.free(ciphertext);

            const decrypted = try testing.allocator.alloc(u8, message_len);
            defer testing.allocator.free(decrypted);

            // Encode first block from a valid u128 value
            const value: u128 = 0xDEADBEEFCAFEBABE_0123456789ABCDEF;
            hctr3fp.encodeBaseRadix(value, radix, plaintext[0..first_len]);

            // Fill tail with valid digits (if any)
            if (tail_size > 0) {
                for (plaintext[first_len..], 0..) |*p, i| {
                    p.* = @intCast((i * 7 + 13) % radix);
                }
            }

            // Create unique tweak for this test case
            var tweak_buf: [64]u8 = undefined;
            const tweak = std.fmt.bufPrint(&tweak_buf, "radix_{}_size_{}", .{ radix, message_len }) catch unreachable;

            // Encrypt
            try cipher.encrypt(ciphertext, plaintext, tweak);

            // Verify all ciphertext digits are in valid range
            for (ciphertext) |c| {
                try testing.expect(c < radix);
            }

            // Verify ciphertext differs from plaintext (unless message is too short)
            if (message_len > first_len + 5) {
                try testing.expect(!std.mem.eql(u8, plaintext, ciphertext));
            }

            // Decrypt
            try cipher.decrypt(decrypted, ciphertext, tweak);

            // Verify round-trip
            try testing.expectEqualSlices(u8, plaintext, decrypted);
        }
    }
}
