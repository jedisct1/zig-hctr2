const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = crypto.onetimeauth.Polyval;

/// HCTR2+FP with AES-128 encryption and decimal (radix-10) format preservation.
pub const Hctr2Fp_128_Decimal = Hctr2Fp(aes.Aes128, 10);

/// HCTR2+FP with AES-256 encryption and decimal (radix-10) format preservation.
pub const Hctr2Fp_256_Decimal = Hctr2Fp(aes.Aes256, 10);

/// HCTR2+FP with AES-128 encryption and hexadecimal (radix-16) format preservation.
pub const Hctr2Fp_128_Hex = Hctr2Fp(aes.Aes128, 16);

/// HCTR2+FP with AES-256 encryption and hexadecimal (radix-16) format preservation.
pub const Hctr2Fp_256_Hex = Hctr2Fp(aes.Aes256, 16);

/// HCTR2+FP with AES-128 encryption and base-64 (radix-64) format preservation.
pub const Hctr2Fp_128_Base64 = Hctr2Fp(aes.Aes128, 64);

/// HCTR2+FP with AES-256 encryption and base-64 (radix-64) format preservation.
pub const Hctr2Fp_256_Base64 = Hctr2Fp(aes.Aes256, 64);

/// Compute the minimum number of base-RADIX digits needed to represent 128 bits.
/// This is: ceil(128 / log₂(RADIX)) = smallest k where RADIX^k >= 2^128
fn computeFirstBlockLength(comptime radix: u16) comptime_int {
    if (radix < 2) @compileError("radix must be >= 2");
    if (radix > 256) @compileError("radix must be <= 256");

    // Special case: radix=256 is identical to standard HCTR2
    if (radix == 256) return 16;

    // Power-of-2 radixes: each digit requires log₂(radix) bits
    // Use ceiling division to ensure we have enough digits
    if (comptime isPowerOfTwo(radix)) {
        const bits_per_digit = @as(u32, @ctz(@as(u16, radix)));
        return (128 + bits_per_digit - 1) / bits_per_digit;
    }

    // Find smallest k where radix^k >= 2^128
    var k: u32 = 1;
    var capacity: u256 = radix;
    const target: u256 = @as(u256, 1) << 128;

    while (capacity < target) : (k += 1) {
        capacity *= radix;
    }

    return k;
}

/// Check if a number is a power of two at compile time.
inline fn isPowerOfTwo(comptime n: u16) bool {
    return n > 0 and (n & (n - 1)) == 0;
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

    // Power-of-2 fast path: use bit shifting and masking instead of division
    if (comptime isPowerOfTwo(radix)) {
        const bits_per_digit = @ctz(@as(u16, radix));
        const mask: u128 = (@as(u128, 1) << @intCast(bits_per_digit)) - 1;
        var bits = value;

        for (output) |*digit| {
            digit.* = @intCast(bits & mask);
            bits >>= @intCast(bits_per_digit);
        }

        // Verify no overflow - remaining bits should be 0
        assert(bits == 0);
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
/// Returns error.InvalidDigit if any digit >= radix (debug builds only).
pub fn decodeBaseRadix(digits: []const u8, comptime radix: u16) !u128 {
    if (radix < 2 or radix > 256) @compileError("radix must be in [2, 256]");

    // Special case: radix=256
    if (comptime radix == 256) {
        assert(digits.len == 16);
        return mem.readInt(u128, digits[0..16], .little);
    }

    // Validate all digits are in range [0, radix) - debug builds only
    if (comptime std.debug.runtime_safety) {
        for (digits) |d| {
            if (d >= radix) return error.InvalidDigit;
        }
    }

    // Power-of-2 fast path: use bit shifting and OR instead of multiplication
    if (comptime isPowerOfTwo(radix)) {
        const bits_per_digit = @ctz(@as(u16, radix));
        var value: u128 = 0;

        for (digits, 0..) |digit, i| {
            const shift = @as(u7, @intCast(i * bits_per_digit));
            value |= @as(u128, digit) << shift;
        }

        return value;
    }

    // Accumulate from most significant to least significant (reverse order)
    // For valid inputs (verified in debug builds), the value is < 2^128 and all
    // intermediate values are also < 2^128, so regular arithmetic is safe.
    var value: u128 = 0;
    var i = digits.len;
    while (i > 0) {
        i -= 1;
        value = value * radix + digits[i];
    }

    return value;
}

/// HCTR2+FP (Format-Preserving) is a variant of HCTR2 that preserves the format of the input.
///
/// While standard HCTR2 operates on arbitrary bytes, HCTR2+FP ensures that ciphertext
/// consists only of digits in a specified radix (e.g., decimal digits 0-9 for radix-10).
///
/// Construction differences from HCTR2:
/// - First block uses base-radix encoding (variable length based on radix)
/// - Modular arithmetic instead of XOR for tail encryption
/// - Input validation to ensure all digits are in valid range [0, radix)
///
/// Use cases:
/// - Encrypting credit card numbers (decimal)
/// - Encrypting alphanumeric identifiers (hexadecimal or custom radix)
/// - Systems requiring format-preserving encryption
///
/// Security properties:
/// - Ciphertext length equals plaintext length
/// - All ciphertext digits are in range [0, radix)
/// - Requires unique (key, tweak) pairs for security
/// - No authentication - consider AEAD if integrity protection is needed
/// - Minimum message length depends on radix (e.g., 39 digits for decimal)
///
/// Type parameters:
/// - `Aes`: AES variant (Aes128 or Aes256)
/// - `radix`: Base for digit representation (2-256)
pub fn Hctr2Fp(comptime Aes: anytype, comptime radix: u16) type {
    // Enforce radix bounds: must be in [2, 256]
    // All overflow handling and arithmetic in this implementation assumes radix <= 256
    if (radix < 2 or radix > 256) @compileError("radix must be in [2, 256]");

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

        /// Authentication tag length (0 - HCTR2+FP is unauthenticated).
        pub const tag_length = 0;

        /// Nonce length (0 - HCTR2+FP uses tweaks instead).
        pub const nonce_length = 0;

        /// Encryption key length in bytes (16 for AES-128, 32 for AES-256).
        pub const key_length = Aes.key_bits / 8;

        /// First block length in digits (radix-dependent, e.g., 39 for decimal).
        pub const first_block_length = first_block_len;

        /// Minimum message length in digits (same as first_block_length).
        pub const min_message_length = first_block_len;

        /// AES block length in bytes (always 16).
        pub const block_length = aes_block_length;

        /// Initialize HCTR2+FP cipher state from an encryption key.
        ///
        /// Parameters:
        /// - `key`: Encryption key (16 bytes for AES-128, 32 bytes for AES-256)
        ///
        /// Returns: Initialized cipher state ready for encryption/decryption operations.
        pub fn init(key: [Aes.key_bits / 8]u8) State {
            const ks_enc = Aes.initEnc(key);
            const ks_dec = AesDecryptCtx.initFromEnc(ks_enc);

            // Generate h and l parameters using AES encryption
            var block_bytes = @as([aes_block_length]u8, @splat(0)) ++ [_]u8{1} ++ @as([aes_block_length - 1]u8, @splat(0));
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

        /// Encrypt plaintext to ciphertext using HCTR2+FP.
        ///
        /// All input digits must be in range [0, radix). Output will also be in this range.
        ///
        /// Parameters:
        /// - `state`: Initialized cipher state
        /// - `ciphertext`: Output buffer (must be same length as plaintext)
        /// - `plaintext`: Input data to encrypt (minimum length: first_block_length)
        /// - `tweak`: Tweak value for domain separation (can be empty, but must be unique per message with same key)
        ///
        /// Returns:
        /// - `error.InputTooShort` if plaintext is less than first_block_length
        /// - `error.InvalidDigit` if any digit >= radix (debug builds only)
        ///
        /// Security: Never reuse the same (key, tweak) pair for different messages.
        pub fn encrypt(state: *State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            try state.hctr2fp(ciphertext, plaintext, tweak, .encrypt);
        }

        /// Decrypt ciphertext to plaintext using HCTR2+FP.
        ///
        /// All input digits must be in range [0, radix). Output will also be in this range.
        ///
        /// Parameters:
        /// - `state`: Initialized cipher state
        /// - `plaintext`: Output buffer (must be same length as ciphertext)
        /// - `ciphertext`: Input data to decrypt (minimum length: first_block_length)
        /// - `tweak`: Tweak value used during encryption
        ///
        /// Returns:
        /// - `error.InputTooShort` if ciphertext is less than first_block_length
        /// - `error.InvalidDigit` if any digit >= radix (debug builds only)
        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            try state.hctr2fp(plaintext, ciphertext, tweak, .decrypt);
        }

        fn hctr2fp(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
            assert(dst.len == src.len);
            if (src.len < first_block_len) {
                return error.InputTooShort;
            }

            // Validate all input digits are in valid range - debug builds only
            if (comptime std.debug.runtime_safety) {
                for (src) |digit| {
                    if (digit >= radix) return error.InvalidDigit;
                }
            }

            const first_part = src[0..first_block_len];
            const tail = src[first_block_len..];

            // Hash tweak with Polyval
            var block_bytes: [aes_block_length]u8 = @splat(0);
            const tweak_len_bits = tweak.len * 8;
            const tweak_len_bytes = if (tail.len % aes_block_length == 0) 2 * tweak_len_bits + 2 else 2 * tweak_len_bits + 3;
            mem.writeInt(u128, &block_bytes, tweak_len_bytes, .little);
            var poly = state.poly;
            poly.update(&block_bytes);

            poly.update(tweak);
            const pad_len = (0 -% tweak.len) % hash_block_length;
            if (pad_len > 0) {
                const pad: [hash_block_length]u8 = @splat(0);
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
                const pad = [_]u8{1} ++ @as([hash_block_length - 1]u8, @splat(0));
                poly.update(pad[0..pad_len]);
            }
            var hh: [Polyval.mac_length]u8 = undefined;
            poly.final(&hh);
            return hh;
        }

        /// Format-Preserving XCTR mode: encrypts/decrypts using one AES block per digit.
        ///
        /// We generate one AES block per digit, convert it to
        /// a 128-bit integer, and reduce modulo radix to get the keystream digit.
        fn fpXctr(state: *const State, dst: []u8, src: []const u8, seed: [aes_block_length]u8, comptime dir: Direction) void {
            assert(dst.len == src.len);

            const batch = Aes.block.parallel.optimal_parallel_blocks;
            var blocks: [aes_block_length * batch]u8 = undefined;
            var counter: u64 = 1;
            var i: usize = 0;

            // Power-of-2 fast path: use bitwise AND instead of modulo
            if (comptime isPowerOfTwo(radix)) {
                const mask: u16 = radix - 1;

                // Batched processing
                while (i + batch <= src.len) : (i += batch) {
                    inline for (0..batch) |j| {
                        const offset = j * aes_block_length;
                        mem.writeInt(u64, blocks[offset..][0..8], counter + j, .little);
                        @memset(blocks[offset..][8..aes_block_length], 0);
                        for (blocks[offset..][0..aes_block_length], seed) |*p, s| p.* ^= s;
                    }
                    counter += batch;

                    state.ks_enc.encryptWide(batch, &blocks, &blocks);

                    inline for (0..batch) |j| {
                        const ks_digit: u8 = @intCast(@as(u16, blocks[j * aes_block_length]) & mask);
                        if (comptime dir == .encrypt) {
                            dst[i + j] = @intCast((@as(u16, src[i + j]) + ks_digit) & mask);
                        } else {
                            dst[i + j] = @intCast((@as(u16, src[i + j]) + radix - ks_digit) & mask);
                        }
                    }
                }

                // Remaining digits
                while (i < src.len) : (i += 1) {
                    mem.writeInt(u64, blocks[0..8], counter, .little);
                    @memset(blocks[8..aes_block_length], 0);
                    for (blocks[0..aes_block_length], seed) |*p, s| p.* ^= s;
                    counter += 1;

                    state.ks_enc.encrypt(blocks[0..aes_block_length], blocks[0..aes_block_length]);

                    const ks_digit: u8 = @intCast(@as(u16, blocks[0]) & mask);
                    if (comptime dir == .encrypt) {
                        dst[i] = @intCast((@as(u16, src[i]) + ks_digit) & mask);
                    } else {
                        dst[i] = @intCast((@as(u16, src[i]) + radix - ks_digit) & mask);
                    }
                }

                return;
            }

            // General case: use full modulo arithmetic
            // Batched processing
            while (i + batch <= src.len) : (i += batch) {
                inline for (0..batch) |j| {
                    const offset = j * aes_block_length;
                    mem.writeInt(u64, blocks[offset..][0..8], counter + j, .little);
                    @memset(blocks[offset..][8..aes_block_length], 0);
                    for (blocks[offset..][0..aes_block_length], seed) |*p, s| p.* ^= s;
                }
                counter += batch;

                state.ks_enc.encryptWide(batch, &blocks, &blocks);

                inline for (0..batch) |j| {
                    const ks_digit: u8 = @intCast(mem.readInt(u128, blocks[j * aes_block_length ..][0..aes_block_length], .little) % radix);
                    if (comptime dir == .encrypt) {
                        dst[i + j] = @intCast((@as(u16, src[i + j]) + ks_digit) % radix);
                    } else {
                        dst[i + j] = @intCast((@as(u16, src[i + j]) + radix - ks_digit) % radix);
                    }
                }
            }

            // Remaining digits
            while (i < src.len) : (i += 1) {
                mem.writeInt(u64, blocks[0..8], counter, .little);
                @memset(blocks[8..aes_block_length], 0);
                for (blocks[0..aes_block_length], seed) |*p, s| p.* ^= s;
                counter += 1;

                state.ks_enc.encrypt(blocks[0..aes_block_length], blocks[0..aes_block_length]);

                const ks_digit: u8 = @intCast(mem.readInt(u128, blocks[0..aes_block_length], .little) % radix);
                if (comptime dir == .encrypt) {
                    dst[i] = @intCast((@as(u16, src[i]) + ks_digit) % radix);
                } else {
                    dst[i] = @intCast((@as(u16, src[i]) + radix - ks_digit) % radix);
                }
            }
        }
    };
}
