const std = @import("std");
const mem = std.mem;

/// Reads a 16-byte little-endian block as one number.
/// `mem.readInt` does the same, but compiles to byte-by-byte code for 128-bit values.
pub fn loadBlock(bytes: *const [16]u8) u128 {
    return mem.littleToNative(u128, mem.bytesToValue(u128, bytes));
}

pub fn storeBlock(bytes: *[16]u8, v: u128) void {
    mem.bytesAsValue(u128, bytes).* = mem.nativeToLittle(u128, v);
}
