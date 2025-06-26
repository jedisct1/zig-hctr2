const std = @import("std");
const testing = std.testing;

// Direct LFSR implementation for testing
fn lfsr_next_128(state: [16]u8) [16]u8 {
    var result = state;

    // Extract MSB and create mask (all 1s if MSB set, all 0s otherwise)
    const msb = result[15] >> 7;
    const mask = -%msb; // Two's complement: 0x00 -> 0x00, 0x01 -> 0xFF

    // Shift left by 1 bit
    var carry: u8 = 0;
    for (&result) |*byte| {
        const new_carry = (byte.* & 0x80) >> 7;
        byte.* = (byte.* << 1) | carry;
        carry = new_carry;
    }

    // Apply feedback polynomial unconditionally using mask
    // Using primitive polynomial: x^128 + x^7 + x^2 + x + 1
    // This is a standard primitive polynomial for 128-bit LFSRs
    result[0] ^= 0x87 & mask; // Represents x^7 + x^2 + x + 1 in the low byte

    return result;
}

fn lfsr_next_256(state: [32]u8) [32]u8 {
    var result = state;

    // Extract MSB and create mask (all 1s if MSB set, all 0s otherwise)
    const msb = result[31] >> 7;
    const mask = -%msb; // Two's complement: 0x00 -> 0x00, 0x01 -> 0xFF

    // Shift left by 1 bit
    var carry: u8 = 0;
    for (&result) |*byte| {
        const new_carry = (byte.* & 0x80) >> 7;
        byte.* = (byte.* << 1) | carry;
        carry = new_carry;
    }

    // Apply feedback polynomial unconditionally using mask
    // x^256 + x^254 + x^251 + x^246 + 1
    // The x^256 term is implicit (it's the feedback itself)
    // We need to XOR at positions: 254, 251, 246, and 0

    // Position 0 (constant term)
    result[0] ^= 0x01 & mask;

    // Position 246: byte 30, bit 6
    result[30] ^= 0x40 & mask;

    // Position 251: byte 31, bit 3
    result[31] ^= 0x08 & mask;

    // Position 254: byte 31, bit 6
    result[31] ^= 0x40 & mask;

    return result;
}

test "128-bit LFSR basic operation" {
    // Test that the LFSR produces different states for 128-bit blocks
    const initial_state = [_]u8{0x01} ++ [_]u8{0x00} ** 15;

    var state1 = initial_state;
    var state2 = lfsr_next_128(state1);
    var state3 = lfsr_next_128(state2);

    // States should all be different
    try testing.expect(!std.mem.eql(u8, &state1, &state2));
    try testing.expect(!std.mem.eql(u8, &state2, &state3));
    try testing.expect(!std.mem.eql(u8, &state1, &state3));
}

test "256-bit LFSR basic operation" {
    // Test that the LFSR produces different states for 256-bit blocks
    const initial_state = [_]u8{0x01} ++ [_]u8{0x00} ** 31;

    var state1 = initial_state;
    var state2 = lfsr_next_256(state1);
    var state3 = lfsr_next_256(state2);

    // States should all be different
    try testing.expect(!std.mem.eql(u8, &state1, &state2));
    try testing.expect(!std.mem.eql(u8, &state2, &state3));
    try testing.expect(!std.mem.eql(u8, &state1, &state3));
}

test "256-bit LFSR feedback polynomial" {
    // Test specific case where feedback should be applied
    // Start with all 1s in the MSB position to trigger feedback
    const state = [_]u8{0x00} ** 31 ++ [_]u8{0x80};

    const next_state = lfsr_next_256(state);

    // After shift, the MSB (0x80) becomes 0x00, and feedback is applied
    // The feedback polynomial x^256 + x^254 + x^251 + x^246 + 1 means:
    // - bit 254 (byte 31, bit 6) should be set: 0x40
    // - bit 251 (byte 31, bit 3) should be set: 0x08
    // - bit 246 (byte 30, bit 6) should be set
    // - bit 0 (byte 0, bit 0) should be set: 0x01
    try testing.expect(next_state[31] == (0x00 | 0x40 | 0x08)); // bits 254 and 251
    try testing.expect(next_state[30] == 0x40); // bit 246
    try testing.expect(next_state[0] == 0x01); // bit 0
}

test "256-bit LFSR period test" {
    // Test that LFSR has a long period (doesn't repeat quickly)
    const initial_state = [_]u8{0x01} ++ [_]u8{0x00} ** 31;
    var state = initial_state;

    // Run for a reasonable number of iterations
    const iterations = 1000;
    for (0..iterations) |_| {
        state = lfsr_next_256(state);
    }

    // Should not have returned to initial state
    try testing.expect(!std.mem.eql(u8, &state, &initial_state));
}

test "256-bit LFSR shift behavior" {
    // Test basic shift behavior
    var state = [_]u8{0x00} ** 31 ++ [_]u8{0x01};

    // After one shift, bit should move to position 1
    state = lfsr_next_256(state);
    try testing.expect(state[31] == 0x02);
    try testing.expect(state[0] == 0x00);

    // After another shift, bit should move to position 2
    state = lfsr_next_256(state);
    try testing.expect(state[31] == 0x04);
    try testing.expect(state[0] == 0x00);
}
