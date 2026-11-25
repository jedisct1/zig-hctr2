const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = @import("polyval.zig").Polyval(1);
const absorb = @import("hctr2.zig").absorb;
const lengthBlock = @import("hctr2.zig").lengthBlock;
const loadBlock = @import("block.zig").loadBlock;
const storeBlock = @import("block.zig").storeBlock;
const lfsrStep = @import("hctr3.zig").lfsrStep;
const hctr2fp = @import("hctr2fp.zig");

/// HCTR3+FP with AES-128 encryption, SHA-256 tweak hashing, and decimal (radix-10) format preservation.
pub const Hctr3Fp_128_Decimal = Hctr3Fp(aes.Aes128, crypto.hash.sha2.Sha256, 10);

/// HCTR3+FP with AES-256 encryption, SHA-256 tweak hashing, and decimal (radix-10) format preservation.
pub const Hctr3Fp_256_Decimal = Hctr3Fp(aes.Aes256, crypto.hash.sha2.Sha256, 10);

/// HCTR3+FP with AES-128 encryption, SHA-256 tweak hashing, and hexadecimal (radix-16) format preservation.
pub const Hctr3Fp_128_Hex = Hctr3Fp(aes.Aes128, crypto.hash.sha2.Sha256, 16);

/// HCTR3+FP with AES-256 encryption, SHA-256 tweak hashing, and hexadecimal (radix-16) format preservation.
pub const Hctr3Fp_256_Hex = Hctr3Fp(aes.Aes256, crypto.hash.sha2.Sha256, 16);

/// HCTR3+FP with AES-128 encryption, SHA-256 tweak hashing, and base-64 (radix-64) format preservation.
pub const Hctr3Fp_128_Base64 = Hctr3Fp(aes.Aes128, crypto.hash.sha2.Sha256, 64);

/// HCTR3+FP with AES-256 encryption, SHA-256 tweak hashing, and base-64 (radix-64) format preservation.
pub const Hctr3Fp_256_Base64 = Hctr3Fp(aes.Aes256, crypto.hash.sha2.Sha256, 64);

pub const encodeBaseRadix = hctr2fp.encodeBaseRadix;
pub const decodeBaseRadix = hctr2fp.decodeBaseRadix;
const computeFirstBlockLength = hctr2fp.computeFirstBlockLength;
const isPowerOfTwo = hctr2fp.isPowerOfTwo;

/// HCTR3+FP (Format-Preserving) combines HCTR3's enhanced security with format preservation.
///
/// HCTR3+FP extends HCTR3 with format-preserving encryption, ensuring that ciphertext
/// consists only of digits in a specified radix (e.g., decimal digits 0-9 for radix-10).
///
/// Construction features:
/// - Two-key construction (encryption key + derived authentication key)
/// - SHA-256 hashing of tweaks for domain separation
/// - fpElk mode (Format-Preserving Encrypted LFSR Keystream) - novel combination
/// - Base-radix encoding for first block
/// - Modular arithmetic with LFSR-based keystream
/// - Constant-time LFSR implementation
///
/// Use cases:
/// - Encrypting credit card numbers with enhanced security (decimal)
/// - Encrypting sensitive alphanumeric identifiers (hexadecimal or custom radix)
/// - Systems requiring both format preservation and strong security bounds
///
/// Security properties:
/// - Ciphertext length equals plaintext length
/// - All ciphertext digits are in range [0, radix)
/// - Stronger security bounds than HCTR2+FP
/// - Requires unique (key, tweak) pairs for security
/// - No authentication - consider AEAD if integrity protection is needed
/// - Minimum message length depends on radix (e.g., 39 digits for decimal)
///
/// Type parameters:
/// - `Aes`: AES variant (Aes128 or Aes256)
/// - `Hash`: Hash function for tweak processing (typically SHA-256)
/// - `radix`: Base for digit representation (2-256)
pub fn Hctr3Fp(comptime Aes: anytype, comptime Hash: anytype, comptime radix: u16) type {
    // Enforce radix bounds: must be in [2, 256]
    // All overflow handling and arithmetic in this implementation assumes radix <= 256
    if (radix < 2 or radix > 256) @compileError("radix must be in [2, 256]");

    const AesEncryptCtx = aes.AesEncryptCtx(Aes);
    const AesDecryptCtx = aes.AesDecryptCtx(Aes);
    const Block = Aes.block;

    const aes_block_length = Block.block_length;
    const hash_digest_length = Hash.digest_length;
    const first_block_len = computeFirstBlockLength(radix);

    return struct {
        const State = @This();

        ks_enc: AesEncryptCtx,
        ks_dec: AesDecryptCtx,
        ke_enc: AesEncryptCtx,
        ke_dec: AesDecryptCtx,
        poly: Polyval,
        l: [aes_block_length]u8,

        /// Authentication tag length (0 - HCTR3+FP is unauthenticated).
        pub const tag_length = 0;

        /// Nonce length (0 - HCTR3+FP uses tweaks instead).
        pub const nonce_length = 0;

        /// Encryption key length in bytes (16 for AES-128, 32 for AES-256).
        pub const key_length = Aes.key_bits / 8;

        /// First block length in digits (radix-dependent, e.g., 39 for decimal).
        pub const first_block_length = first_block_len;

        /// Minimum message length in digits (same as first_block_length).
        pub const min_message_length = first_block_len;

        /// AES block length in bytes (always 16).
        pub const block_length = aes_block_length;

        /// Initialize HCTR3+FP cipher state from an encryption key.
        ///
        /// Derives a secondary authentication key (Ke) from the encryption key for the two-key construction.
        ///
        /// Parameters:
        /// - `key`: Encryption key (16 bytes for AES-128, 32 bytes for AES-256)
        ///
        /// Returns: Initialized cipher state ready for encryption/decryption operations.
        pub fn init(key: [Aes.key_bits / 8]u8) State {
            const ks_enc = Aes.initEnc(key);
            const ks_dec = AesDecryptCtx.initFromEnc(ks_enc);

            // Derive Ke (authentication key)
            var ke_bytes: [aes_block_length]u8 = @splat(0);
            ks_enc.encrypt(&ke_bytes, &ke_bytes);

            // Handle different key sizes
            var ke_key: [key_length]u8 = undefined;
            if (key_length <= aes_block_length) {
                @memcpy(&ke_key, ke_bytes[0..key_length]);
            } else {
                // For larger keys, we need multiple blocks
                @memcpy(ke_key[0..aes_block_length], &ke_bytes);
                var extra_block: [aes_block_length]u8 = @splat(1);
                ks_enc.encrypt(&extra_block, &extra_block);
                @memcpy(ke_key[aes_block_length..], extra_block[0..(key_length - aes_block_length)]);
            }

            const ke_enc = Aes.initEnc(ke_key);
            const ke_dec = AesDecryptCtx.initFromEnc(ke_enc);

            // Derive Kh and L using ke
            var kh_bytes: [aes_block_length]u8 = @splat(0);
            ke_enc.encrypt(&kh_bytes, &kh_bytes);

            var l_bytes: [aes_block_length]u8 = @as([aes_block_length - 1]u8, @splat(0)) ++ [_]u8{1};
            ke_enc.encrypt(&l_bytes, &l_bytes);

            const poly = Polyval.init(.{kh_bytes});

            return State{
                .ks_enc = ks_enc,
                .ks_dec = ks_dec,
                .ke_enc = ke_enc,
                .ke_dec = ke_dec,
                .poly = poly,
                .l = l_bytes,
            };
        }

        const Direction = enum { encrypt, decrypt };

        /// Encrypt plaintext to ciphertext using HCTR3+FP.
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
        /// - `error.Overflow` if the first block encodes a value >= 2^128
        ///
        /// Security: Never reuse the same (key, tweak) pair for different messages.
        pub fn encrypt(state: *State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            try state.hctr3fp(ciphertext, plaintext, tweak, .encrypt);
        }

        /// Decrypt ciphertext to plaintext using HCTR3+FP.
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
        /// - `error.Overflow` if the first block encodes a value >= 2^128
        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            try state.hctr3fp(plaintext, ciphertext, tweak, .decrypt);
        }

        fn hctr3fp(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
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

            // Step 1: Hash the tweak/associated data to a single block (HCTR3 style)
            var t: [aes_block_length]u8 = undefined;
            var hasher = Hash.init(.{});
            hasher.update(tweak);
            var hash_out: [hash_digest_length]u8 = undefined;
            hasher.final(&hash_out);

            // Truncate or pad hash to block size
            if (hash_digest_length >= aes_block_length) {
                @memcpy(&t, hash_out[0..aes_block_length]);
            } else {
                @memcpy(t[0..hash_digest_length], &hash_out);
                @memset(t[hash_digest_length..], 0);
            }

            // Step 2: Process with POLYVAL
            const block_bytes = lengthBlock(tweak.len, tail.len);
            var poly = state.poly.hasher();
            poly.update(&block_bytes);

            // Update with hashed tweak
            poly.update(&t);

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

                // 4. Compute seed for fpElk
                var s = mm;
                for (&s, uu, state.l) |*p, x, y| {
                    p.* ^= x ^ y;
                }

                // 5. Format-preserving ELK on tail
                const v = dst[first_block_len..];
                fpElk(state, v, tail, s, .encrypt);

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

                // 4. Compute seed for fpElk
                var s = mm;
                for (&s, uu, state.l) |*p, x, y| {
                    p.* ^= x ^ y;
                }

                // 5. Format-preserving ELK decrypt
                const n = dst[first_block_len..];
                fpElk(state, n, tail, s, .decrypt);

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

        /// Format-Preserving Encrypted LFSR Keystream (fpELK) mode.
        ///
        /// For power-of-2 radixes, we extract multiple digits from each AES block.
        /// For other radixes, we generate one AES block per digit and reduce modulo radix.
        fn fpElk(state: *const State, dst: []u8, src: []const u8, seed: [aes_block_length]u8, comptime dir: Direction) void {
            assert(dst.len == src.len);

            const batch = Aes.block.parallel.optimal_parallel_blocks;
            var blocks: [aes_block_length * batch]u8 = undefined;
            var lfsr = loadBlock(&seed);
            var i: usize = 0;

            // Power-of-2 fast path: extract multiple digits from each AES block
            if (comptime isPowerOfTwo(radix)) {
                const bits_per_digit = @ctz(radix);
                const digits_per_block = 128 / @as(usize, bits_per_digit);
                const mask: u128 = radix - 1;

                var block: [aes_block_length]u8 = undefined;

                // Process in chunks of digits_per_block
                while (i + digits_per_block <= src.len) : (i += digits_per_block) {
                    // Generate keystream block
                    storeBlock(&block, lfsr);
                    lfsr = lfsrStep(lfsr);
                    state.ke_enc.encrypt(&block, &block);
                    var keystream = loadBlock(&block);

                    // Process all digits from this block
                    inline for (0..digits_per_block) |j| {
                        const ks_digit: u8 = @intCast(keystream & mask);
                        const adjustment = if (dir == .encrypt) ks_digit else radix - ks_digit;
                        dst[i + j] = @intCast((@as(u16, src[i + j]) + adjustment) & mask);
                        keystream >>= bits_per_digit;
                    }
                }

                // Handle remaining digits
                if (i < src.len) {
                    storeBlock(&block, lfsr);
                    lfsr = lfsrStep(lfsr);
                    state.ke_enc.encrypt(&block, &block);
                    var keystream = loadBlock(&block);

                    while (i < src.len) : (i += 1) {
                        const ks_digit: u8 = @intCast(keystream & mask);
                        const adjustment = if (dir == .encrypt) ks_digit else radix - ks_digit;
                        dst[i] = @intCast((@as(u16, src[i]) + adjustment) & mask);
                        keystream >>= bits_per_digit;
                    }
                }

                return;
            }

            // General case: use full modulo arithmetic
            // Batched processing
            while (i + batch <= src.len) : (i += batch) {
                inline for (0..batch) |j| {
                    storeBlock(blocks[j * aes_block_length ..][0..aes_block_length], lfsr);
                    lfsr = lfsrStep(lfsr);
                }

                state.ke_enc.encryptWide(batch, &blocks, &blocks);

                inline for (0..batch) |j| {
                    const ks_digit: u8 = @intCast(loadBlock(blocks[j * aes_block_length ..][0..aes_block_length]) % radix);
                    if (comptime dir == .encrypt) {
                        dst[i + j] = @intCast((@as(u16, src[i + j]) + ks_digit) % radix);
                    } else {
                        dst[i + j] = @intCast((@as(u16, src[i + j]) + radix - ks_digit) % radix);
                    }
                }
            }

            // Remaining digits
            while (i < src.len) : (i += 1) {
                storeBlock(blocks[0..aes_block_length], lfsr);
                lfsr = lfsrStep(lfsr);

                state.ke_enc.encrypt(blocks[0..aes_block_length], blocks[0..aes_block_length]);

                const ks_digit: u8 = @intCast(loadBlock(blocks[0..aes_block_length]) % radix);
                if (comptime dir == .encrypt) {
                    dst[i] = @intCast((@as(u16, src[i]) + ks_digit) % radix);
                } else {
                    dst[i] = @intCast((@as(u16, src[i]) + radix - ks_digit) % radix);
                }
            }
        }
    };
}
