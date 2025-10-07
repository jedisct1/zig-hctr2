const std = @import("std");
const testing = std.testing;
const hctr3 = @import("hctr3.zig");

test "HCTR3-128 basic encryption/decryption" {
    const key: [16]u8 = @splat(0x01);
    const tweak = "test tweak data";
    const plaintext = "Hello, this is a test message that is longer than one block!";

    var state = hctr3.Hctr3_128.init(key);

    var ciphertext: [plaintext.len]u8 = undefined;
    try state.encrypt(&ciphertext, plaintext, tweak);

    var decrypted: [plaintext.len]u8 = undefined;
    try state.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "HCTR3-256 basic encryption/decryption" {
    const key: [32]u8 = @splat(0x02);
    const tweak = "another test tweak";
    const plaintext = "This is another test message for HCTR3-256 with a longer key size!";

    var state = hctr3.Hctr3_256.init(key);

    var ciphertext: [plaintext.len]u8 = undefined;
    try state.encrypt(&ciphertext, plaintext, tweak);

    var decrypted: [plaintext.len]u8 = undefined;
    try state.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "HCTR3 with empty tweak" {
    const key: [16]u8 = @splat(0x03);
    const tweak = "";
    const plaintext = "Test with empty tweak";

    var state = hctr3.Hctr3_128.init(key);

    var ciphertext: [plaintext.len]u8 = undefined;
    try state.encrypt(&ciphertext, plaintext, tweak);

    var decrypted: [plaintext.len]u8 = undefined;
    try state.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "HCTR3 input too short" {
    const key: [16]u8 = @splat(0x04);
    const tweak = "tweak";
    const plaintext = "short"; // Less than block size

    var state = hctr3.Hctr3_128.init(key);

    var ciphertext: [plaintext.len]u8 = undefined;
    const result = state.encrypt(&ciphertext, plaintext, tweak);

    try testing.expectError(error.InputTooShort, result);
}

test "HCTR3 different tweaks produce different ciphertexts" {
    const key: [16]u8 = @splat(0x05);
    const tweak1 = "tweak1";
    const tweak2 = "tweak2";
    const plaintext = "Same plaintext for both encryptions";

    var state = hctr3.Hctr3_128.init(key);

    var ciphertext1: [plaintext.len]u8 = undefined;
    try state.encrypt(&ciphertext1, plaintext, tweak1);

    var ciphertext2: [plaintext.len]u8 = undefined;
    try state.encrypt(&ciphertext2, plaintext, tweak2);

    // Ciphertexts should be different
    try testing.expect(!std.mem.eql(u8, &ciphertext1, &ciphertext2));
}

test "HCTR3 large message" {
    const key: [16]u8 = @splat(0x06);
    const tweak = "large message tweak";

    // Create a large message (multiple blocks)
    var plaintext: [1024]u8 = undefined;
    for (&plaintext, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    var state = hctr3.Hctr3_128.init(key);

    var ciphertext: [plaintext.len]u8 = undefined;
    try state.encrypt(&ciphertext, &plaintext, tweak);

    var decrypted: [plaintext.len]u8 = undefined;
    try state.decrypt(&decrypted, &ciphertext, tweak);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
