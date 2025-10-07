const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = crypto.onetimeauth.Polyval;

pub const Hctr2Fp_128_Decimal = Hctr2Fp(aes.Aes128, 10);
pub const Hctr2Fp_256_Decimal = Hctr2Fp(aes.Aes256, 10);
pub const Hctr2Fp_128_Hex = Hctr2Fp(aes.Aes128, 16);
pub const Hctr2Fp_256_Hex = Hctr2Fp(aes.Aes256, 16);
pub const Hctr2Fp_128_Base64 = Hctr2Fp(aes.Aes128, 64);
pub const Hctr2Fp_256_Base64 = Hctr2Fp(aes.Aes256, 64);

/// Compute the minimum number of base-RADIX digits needed to represent 128 bits.
/// This is: ceil(128 / log₂(RADIX)) = smallest k where RADIX^k >= 2^128
fn computeFirstBlockLength(comptime radix: u16) comptime_int {
    if (radix < 2) @compileError("radix must be >= 2");
    if (radix > 256) @compileError("radix must be <= 256");

    // Special case: radix=256 is identical to standard HCTR2
    if (radix == 256) return 16;

    // Find smallest k where radix^k >= 2^128
    var k: u32 = 1;
    var capacity: u256 = radix;
    const target: u256 = @as(u256, 1) << 128;

    while (capacity < target) : (k += 1) {
        capacity *= radix;
    }

    return k;
}

/// Encode a 128-bit value as base-RADIX digits (little-endian).
/// The output buffer must have length >= computeFirstBlockLength(radix).
pub fn encodeBaseRadix(value: u128, comptime radix: u16, output: []u8) void {
    if (radix < 2 or radix > 256) @compileError("radix must be in [2, 256]");
    const min_len = comptime computeFirstBlockLength(radix);
    assert(output.len >= min_len);

    // Special case: radix=256 is just byte representation
    if (comptime radix == 256) {
        mem.writeInt(u128, output[0..16], value, .little);
        return;
    }

    // General case: repeated division (little-endian, least significant digit first)
    var remaining = value;
    for (output) |*digit| {
        digit.* = @intCast(remaining % radix);
        remaining /= radix;
    }

    // Verify no overflow - remaining should be 0 if output length is correct
    assert(remaining == 0);
}

/// Decode base-RADIX digits (little-endian) to a 128-bit value.
/// Returns error.InvalidDigit if any digit >= radix.
pub fn decodeBaseRadix(digits: []const u8, comptime radix: u16) !u128 {
    if (radix < 2 or radix > 256) @compileError("radix must be in [2, 256]");

    // Special case: radix=256
    if (comptime radix == 256) {
        assert(digits.len == 16);
        return mem.readInt(u128, digits[0..16], .little);
    }

    // Validate all digits are in range [0, radix)
    for (digits) |d| {
        if (d >= radix) return error.InvalidDigit;
    }

    // Accumulate from most significant to least significant (reverse order)
    var value: u128 = 0;
    var i = digits.len;
    while (i > 0) {
        i -= 1;
        value = value * radix + digits[i];
    }

    return value;
}

pub fn Hctr2Fp(comptime Aes: anytype, comptime radix: u16) type {
    const AesEncryptCtx = aes.AesEncryptCtx(Aes);
    const AesDecryptCtx = aes.AesDecryptCtx(Aes);
    const Block = Aes.block;

    const aes_block_length = Block.block_length;
    const hash_block_length = Polyval.block_length;
    const first_block_len = computeFirstBlockLength(radix);

    return struct {
        const State = @This();

        ks_enc: AesEncryptCtx,
        ks_dec: AesDecryptCtx,
        poly: Polyval,
        h: [Polyval.key_length]u8,
        l: [aes_block_length]u8,

        pub const tag_length = 0;
        pub const nonce_length = 0;
        pub const key_length = Aes.key_bits / 8;
        pub const first_block_length = first_block_len;
        pub const min_message_length = first_block_len;
        pub const block_length = aes_block_length;

        pub fn init(key: [Aes.key_bits / 8]u8) State {
            const ks_enc = Aes.initEnc(key);
            const ks_dec = AesDecryptCtx.initFromEnc(ks_enc);

            // Generate h and l parameters using AES encryption
            var block_bytes = [_]u8{0} ** aes_block_length ++ [_]u8{1} ++ [_]u8{0} ** (aes_block_length - 1);
            ks_enc.encryptWide(2, &block_bytes, &block_bytes);
            const h = block_bytes[0..aes_block_length].*;
            const l = block_bytes[aes_block_length..].*;
            const poly = Polyval.init(&h);

            return State{
                .ks_enc = ks_enc,
                .ks_dec = ks_dec,
                .poly = poly,
                .h = h,
                .l = l,
            };
        }

        const Direction = enum { encrypt, decrypt };

        pub fn encrypt(state: *State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            try state.hctr2fp(ciphertext, plaintext, tweak, .encrypt);
        }

        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            try state.hctr2fp(plaintext, ciphertext, tweak, .decrypt);
        }

        fn hctr2fp(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
            assert(dst.len == src.len);
            if (src.len < first_block_len) {
                return error.InputTooShort;
            }

            // Validate all input digits are in valid range
            for (src) |digit| {
                if (digit >= radix) return error.InvalidDigit;
            }

            const first_part = src[0..first_block_len];
            const tail = src[first_block_len..];

            // Hash tweak with Polyval
            var block_bytes = [_]u8{0} ** aes_block_length;
            const tweak_len_bits = tweak.len * 8;
            const tweak_len_bytes = if (tail.len % aes_block_length == 0) 2 * tweak_len_bits + 2 else 2 * tweak_len_bits + 3;
            mem.writeInt(u128, &block_bytes, tweak_len_bytes, .little);
            var poly = state.poly;
            poly.update(&block_bytes);

            poly.update(tweak);
            const pad_len = (0 -% tweak.len) % hash_block_length;
            if (pad_len > 0) {
                const pad = [_]u8{0} ** hash_block_length;
                poly.update(pad[0..pad_len]);
            }

            const poly_after_tweak = poly;

            if (direction == .encrypt) {
                // Encryption flow
                // 1. Absorb tail into Polyval
                const hh = absorb(&poly, tail);

                // 2. Decode first block and XOR with hash
                const m_bits = try decodeBaseRadix(first_part, radix);
                var mm: [aes_block_length]u8 = undefined;
                mem.writeInt(u128, &mm, m_bits, .little);
                for (&mm, hh) |*p, x| {
                    p.* ^= x;
                }

                // 3. Encrypt with AES
                var uu: [aes_block_length]u8 = undefined;
                state.ks_enc.encrypt(&uu, &mm);

                // 4. Compute seed for XCTR
                var s = mm;
                for (&s, uu, state.l) |*p, x, y| {
                    p.* ^= x ^ y;
                }

                // 5. Format-preserving XCTR on tail
                const v = dst[first_block_len..];
                fpXctr(state, v, tail, s, .encrypt);

                // 6. Re-hash encrypted tail
                poly = poly_after_tweak;
                const hh2 = absorb(&poly, v);

                // 7. Finalize and encode first block
                const u_bytes: [aes_block_length]u8 = blk: {
                    var result: [aes_block_length]u8 = undefined;
                    for (&result, uu, hh2) |*p, x, y| {
                        p.* = x ^ y;
                    }
                    break :blk result;
                };
                const u_bits = mem.readInt(u128, &u_bytes, .little);
                encodeBaseRadix(u_bits, radix, dst[0..first_block_len]);
            } else {
                // Decryption flow
                // 1. Absorb encrypted tail
                const hh2 = absorb(&poly, tail);

                // 2. Decode first block and XOR with hash
                const u_bits = try decodeBaseRadix(first_part, radix);
                var uu: [aes_block_length]u8 = undefined;
                mem.writeInt(u128, &uu, u_bits, .little);
                for (&uu, hh2) |*p, x| {
                    p.* ^= x;
                }

                // 3. Decrypt with AES
                var mm: [aes_block_length]u8 = undefined;
                state.ks_dec.decrypt(&mm, &uu);

                // 4. Compute seed for XCTR
                var s = mm;
                for (&s, uu, state.l) |*p, x, y| {
                    p.* ^= x ^ y;
                }

                // 5. Format-preserving XCTR decrypt
                const n = dst[first_block_len..];
                fpXctr(state, n, tail, s, .decrypt);

                // 6. Re-hash original tail
                poly = poly_after_tweak;
                const hh = absorb(&poly, n);

                // 7. Finalize and encode first block
                const m_bytes: [aes_block_length]u8 = blk: {
                    var result: [aes_block_length]u8 = undefined;
                    for (&result, mm, hh) |*p, x, y| {
                        p.* = x ^ y;
                    }
                    break :blk result;
                };
                const m_bits = mem.readInt(u128, &m_bytes, .little);
                encodeBaseRadix(m_bits, radix, dst[0..first_block_len]);
            }
        }

        fn absorb(poly: *Polyval, msg: []const u8) [Polyval.mac_length]u8 {
            poly.update(msg);
            const pad_len = (0 -% msg.len) % hash_block_length;
            if (pad_len > 0) {
                const pad = [_]u8{1} ++ [_]u8{0} ** (hash_block_length - 1);
                poly.update(pad[0..pad_len]);
            }
            var hh: [Polyval.mac_length]u8 = undefined;
            poly.final(&hh);
            return hh;
        }

        fn fpXctr(state: *const State, dst: []u8, src: []const u8, seed: [aes_block_length]u8, comptime dir: Direction) void {
            assert(dst.len == src.len);

            const batch = Aes.block.parallel.optimal_parallel_blocks;
            const block_length_batch = aes_block_length * batch;
            var counter_bytes_batch: [block_length_batch]u8 = undefined;
            var counter: u64 = 1;
            var i: usize = 0;

            // Batched processing for performance
            if (src.len > block_length_batch) {
                var seed_batch: [block_length_batch]u8 = undefined;
                inline for (0..batch) |j| {
                    @memcpy(seed_batch[j * aes_block_length ..][0..aes_block_length], &seed);
                }

                while (i + block_length_batch <= src.len) : (i += block_length_batch) {
                    // Generate counter blocks
                    inline for (0..batch) |j| {
                        mem.writeInt(u64, counter_bytes_batch[aes_block_length * j ..][0..8], counter, .little);
                        @memset(counter_bytes_batch[aes_block_length * j ..][8..aes_block_length], 0);
                        counter += 1;
                    }

                    // XOR with seed
                    for (&counter_bytes_batch, seed_batch) |*p, s| {
                        p.* ^= s;
                    }

                    // Encrypt batch
                    state.ks_enc.encryptWide(batch, &counter_bytes_batch, &counter_bytes_batch);

                    // Apply modular arithmetic (comptime radix optimizes these operations)
                    for (dst[i..][0..block_length_batch], src[i..][0..block_length_batch], counter_bytes_batch) |*d, s, c| {
                        const keystream_byte: u16 = c % radix;
                        if (comptime dir == .encrypt) {
                            d.* = @intCast((s + keystream_byte) % radix);
                        } else {
                            d.* = @intCast((s + radix - keystream_byte) % radix); // Avoid underflow
                        }
                    }
                }
            }

            // Handle remaining blocks one at a time
            const counter_bytes = counter_bytes_batch[0..aes_block_length];

            while (i + aes_block_length <= src.len) : (i += aes_block_length) {
                mem.writeInt(u64, counter_bytes[0..8], counter, .little);
                @memset(counter_bytes[8..], 0);
                counter += 1;

                for (counter_bytes, seed) |*p, x| {
                    p.* ^= x;
                }

                state.ks_enc.encrypt(counter_bytes, counter_bytes);

                for (dst[i..][0..aes_block_length], src[i..][0..aes_block_length], counter_bytes) |*d, s, c| {
                    const keystream_byte: u16 = c % radix;
                    if (comptime dir == .encrypt) {
                        d.* = @intCast((s + keystream_byte) % radix);
                    } else {
                        d.* = @intCast((s + radix - keystream_byte) % radix);
                    }
                }
            }

            // Handle partial final block
            const left = src.len - i;
            if (left > 0) {
                mem.writeInt(u64, counter_bytes[0..8], counter, .little);
                @memset(counter_bytes[8..], 0);

                for (counter_bytes, seed) |*p, x| {
                    p.* ^= x;
                }

                state.ks_enc.encrypt(counter_bytes, counter_bytes);

                for (dst[i..], src[i..], counter_bytes[0..left]) |*d, s, c| {
                    const keystream_byte: u16 = c % radix;
                    if (comptime dir == .encrypt) {
                        d.* = @intCast((s + keystream_byte) % radix);
                    } else {
                        d.* = @intCast((s + radix - keystream_byte) % radix);
                    }
                }
            }
        }
    };
}
