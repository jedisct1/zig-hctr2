const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = crypto.onetimeauth.Polyval;

/// CHCTR2 (Cascaded HCTR2) with AES-128 encryption.
/// Achieves 2n/3-bit (approximately 85-bit) multi-user security.
pub const Chctr2_128 = Chctr2(aes.Aes128);

/// CHCTR2 (Cascaded HCTR2) with AES-256 encryption.
/// Achieves 2n/3-bit (approximately 85-bit) multi-user security.
pub const Chctr2_256 = Chctr2(aes.Aes256);

/// CHCTR2 (Cascaded HCTR2) is a beyond-birthday-bound secure wide-block tweakable cipher.
///
/// CHCTR2 achieves 2n/3-bit multi-user security (approximately 85 bits with 128-bit blocks)
/// by cascading HCTR2 twice with two independent keys. This provides significantly higher
/// security than standard HCTR2's birthday-bound (64-bit) security.
///
/// Construction (from "Beyond-Birthday-Bound Security with HCTR2", ASIACRYPT 2025):
/// - Uses two independent keys K1 and K2
/// - CHCTR2[K1,K2](T,M) = HCTR2[K2](T, HCTR2[K1](T, M))
/// - Optimized: middle hash layer combines H1 and H2: Z_{1,2} = H1(T,R) ⊕ H2(T,R)
/// - Cost per block: 2 BC calls + 3 field multiplications
///
/// Security properties:
/// - Beyond-birthday-bound: ~85-bit security vs HCTR2's ~64-bit
/// - No restrictions on tweak usage
/// - Multi-user secure
/// - Ciphertext length equals plaintext length
///
/// Type parameters:
/// - `Aes`: AES variant (Aes128 or Aes256)
pub fn Chctr2(comptime Aes: anytype) type {
    const AesEncryptCtx = aes.AesEncryptCtx(Aes);
    const AesDecryptCtx = aes.AesDecryptCtx(Aes);
    const Block = Aes.block;

    const aes_block_length = Block.block_length;
    const hash_block_length = Polyval.block_length;

    return struct {
        const State = @This();

        // First round (K1)
        ks1_enc: AesEncryptCtx,
        ks1_dec: AesDecryptCtx,
        h1: [Polyval.key_length]u8,
        l1: [aes_block_length]u8,

        // Second round (K2)
        ks2_enc: AesEncryptCtx,
        ks2_dec: AesDecryptCtx,
        h2: [Polyval.key_length]u8,
        l2: [aes_block_length]u8,

        /// Authentication tag length (0 - CHCTR2 is unauthenticated).
        pub const tag_length = 0;

        /// Nonce length (0 - CHCTR2 uses tweaks instead).
        pub const nonce_length = 0;

        /// Total key length in bytes (2x AES key: 32 for AES-128, 64 for AES-256).
        pub const key_length = 2 * (Aes.key_bits / 8);

        /// Single AES key length.
        pub const single_key_length = Aes.key_bits / 8;

        /// AES block length in bytes (always 16).
        pub const block_length = aes_block_length;

        /// Initialize CHCTR2 cipher state from two encryption keys.
        ///
        /// Parameters:
        /// - `key`: Combined key (K1 || K2), where each Ki is key_length/2 bytes
        ///
        /// Returns: Initialized cipher state ready for encryption/decryption operations.
        pub fn init(key: [key_length]u8) State {
            const key1 = key[0..single_key_length].*;
            const key2 = key[single_key_length..].*;
            return initSplit(key1, key2);
        }

        /// Initialize CHCTR2 cipher state from two separate encryption keys.
        ///
        /// Parameters:
        /// - `key1`: First encryption key (for inner HCTR2)
        /// - `key2`: Second encryption key (for outer HCTR2)
        ///
        /// Returns: Initialized cipher state ready for encryption/decryption operations.
        pub fn initSplit(key1: [single_key_length]u8, key2: [single_key_length]u8) State {
            // Initialize first round (K1)
            const ks1_enc = Aes.initEnc(key1);
            const ks1_dec = AesDecryptCtx.initFromEnc(ks1_enc);

            var block_bytes1 = @as([aes_block_length]u8, @splat(0)) ++ [_]u8{1} ++ @as([aes_block_length - 1]u8, @splat(0));
            ks1_enc.encryptWide(2, &block_bytes1, &block_bytes1);
            const h1 = block_bytes1[0..aes_block_length].*;
            const l1 = block_bytes1[aes_block_length..].*;

            // Initialize second round (K2)
            const ks2_enc = Aes.initEnc(key2);
            const ks2_dec = AesDecryptCtx.initFromEnc(ks2_enc);

            var block_bytes2 = @as([aes_block_length]u8, @splat(0)) ++ [_]u8{1} ++ @as([aes_block_length - 1]u8, @splat(0));
            ks2_enc.encryptWide(2, &block_bytes2, &block_bytes2);
            const h2 = block_bytes2[0..aes_block_length].*;
            const l2 = block_bytes2[aes_block_length..].*;

            return State{
                .ks1_enc = ks1_enc,
                .ks1_dec = ks1_dec,
                .h1 = h1,
                .l1 = l1,
                .ks2_enc = ks2_enc,
                .ks2_dec = ks2_dec,
                .h2 = h2,
                .l2 = l2,
            };
        }

        const Direction = enum { encrypt, decrypt };

        /// Encrypt plaintext to ciphertext using CHCTR2.
        ///
        /// Parameters:
        /// - `state`: Initialized cipher state
        /// - `ciphertext`: Output buffer (must be same length as plaintext)
        /// - `plaintext`: Input data to encrypt (minimum 16 bytes)
        /// - `tweak`: Tweak value for domain separation
        ///
        /// Returns: `error.InputTooShort` if plaintext is less than 16 bytes.
        pub fn encrypt(state: *State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            try state.chctr2(ciphertext, plaintext, tweak, .encrypt);
        }

        /// Decrypt ciphertext to plaintext using CHCTR2.
        ///
        /// Parameters:
        /// - `state`: Initialized cipher state
        /// - `plaintext`: Output buffer (must be same length as ciphertext)
        /// - `ciphertext`: Input data to decrypt (minimum 16 bytes)
        /// - `tweak`: Tweak value used during encryption
        ///
        /// Returns: `error.InputTooShort` if ciphertext is less than 16 bytes.
        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            try state.chctr2(plaintext, ciphertext, tweak, .decrypt);
        }

        /// Optimized CHCTR2 implementation.
        /// Structure: hash1-encrypt1-hash_{1,2}-encrypt2-hash2
        /// where hash_{1,2}(T,R) = H1(T,R) ⊕ H2(T,R)
        fn chctr2(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
            assert(dst.len == src.len);
            if (src.len < aes_block_length) {
                return error.InputTooShort;
            }

            const m0 = src[0..aes_block_length];
            const m_star = src[aes_block_length..];

            // Compute tweak encoding for Polyval
            var block_bytes: [aes_block_length]u8 = @splat(0);
            const tweak_len_bits = tweak.len * 8;
            const tweak_len_bytes = if (m_star.len % aes_block_length == 0) 2 * tweak_len_bits + 2 else 2 * tweak_len_bits + 3;
            mem.writeInt(u128, &block_bytes, tweak_len_bytes, .little);

            // Initialize both Polyval instances and process tweak
            var poly1 = Polyval.init(&state.h1);
            poly1.update(&block_bytes);
            poly1.update(tweak);
            const pad_len = (0 -% tweak.len) % hash_block_length;
            if (pad_len > 0) {
                const pad: [hash_block_length]u8 = @splat(0);
                poly1.update(pad[0..pad_len]);
            }

            var poly2 = Polyval.init(&state.h2);
            poly2.update(&block_bytes);
            poly2.update(tweak);
            if (pad_len > 0) {
                const pad: [hash_block_length]u8 = @splat(0);
                poly2.update(pad[0..pad_len]);
            }

            // Save state after tweak for later
            const poly1_after_tweak = poly1;
            const poly2_after_tweak = poly2;

            if (direction == .encrypt) {
                // === ENCRYPTION ===
                // Round 1: hash1-encrypt1
                const z1 = absorb(&poly1, m_star);
                var x1_0: [aes_block_length]u8 = undefined;
                for (&x1_0, z1, m0) |*p, z, m| {
                    p.* = z ^ m;
                }

                var y1_0: [aes_block_length]u8 = undefined;
                state.ks1_enc.encrypt(&y1_0, &x1_0);

                var iv1: [aes_block_length]u8 = undefined;
                for (&iv1, x1_0, y1_0, state.l1) |*p, x, y, l| {
                    p.* = x ^ y ^ l;
                }

                // XCTR round 1: M* -> R (use dst as temporary buffer for R)
                // We can use dst[aes_block_length..] as R buffer since we'll overwrite it
                const r_slice = dst[aes_block_length..];
                xctr(state.ks1_enc, r_slice, m_star, iv1);

                // Middle hash: Z_{1,2} = H1(T,R) ⊕ H2(T,R)
                poly1 = poly1_after_tweak;
                poly2 = poly2_after_tweak;
                const h1_r = absorb(&poly1, r_slice);
                const h2_r = absorb(&poly2, r_slice);

                var z1_2: [aes_block_length]u8 = undefined;
                for (&z1_2, h1_r, h2_r) |*p, a, b| {
                    p.* = a ^ b;
                }

                // Compute X2_0 and Y2_0
                var x2_0: [aes_block_length]u8 = undefined;
                for (&x2_0, y1_0, z1_2) |*p, y, z| {
                    p.* = y ^ z;
                }

                var y2_0: [aes_block_length]u8 = undefined;
                state.ks2_enc.encrypt(&y2_0, &x2_0);

                var iv2: [aes_block_length]u8 = undefined;
                for (&iv2, x2_0, y2_0, state.l2) |*p, x, y, l| {
                    p.* = x ^ y ^ l;
                }

                // XCTR round 2: R -> C* (in-place in dst)
                const c_star = dst[aes_block_length..];
                xctr(state.ks2_enc, c_star, r_slice, iv2);

                // Final hash: Z2 = H2(T, C*)
                poly2 = poly2_after_tweak;
                const z2 = absorb(&poly2, c_star);

                // C0 = Y2_0 ⊕ Z2
                const c0 = dst[0..aes_block_length];
                for (c0, y2_0, z2) |*p, y, z| {
                    p.* = y ^ z;
                }
            } else {
                // === DECRYPTION ===
                const c0 = src[0..aes_block_length];
                const c_star = src[aes_block_length..];

                // Compute Z2 = H2(T, C*)
                const z2 = absorb(&poly2, c_star);

                // Y2_0 = C0 ⊕ Z2
                var y2_0: [aes_block_length]u8 = undefined;
                for (&y2_0, c0, z2) |*p, c, z| {
                    p.* = c ^ z;
                }

                // X2_0 = E^{-1}(Y2_0)
                var x2_0: [aes_block_length]u8 = undefined;
                state.ks2_dec.decrypt(&x2_0, &y2_0);

                // IV2 = X2_0 ⊕ Y2_0 ⊕ L2
                var iv2: [aes_block_length]u8 = undefined;
                for (&iv2, x2_0, y2_0, state.l2) |*p, x, y, l| {
                    p.* = x ^ y ^ l;
                }

                // XCTR^{-1} round 2: C* -> R (use dst as temporary buffer)
                const r_slice = dst[aes_block_length..];
                xctr(state.ks2_enc, r_slice, c_star, iv2);

                // Middle hash: Z_{1,2} = H1(T,R) ⊕ H2(T,R)
                poly1 = poly1_after_tweak;
                poly2 = poly2_after_tweak;
                const h1_r = absorb(&poly1, r_slice);
                const h2_r = absorb(&poly2, r_slice);

                var z1_2: [aes_block_length]u8 = undefined;
                for (&z1_2, h1_r, h2_r) |*p, a, b| {
                    p.* = a ^ b;
                }

                // Y1_0 = X2_0 ⊕ Z_{1,2}
                var y1_0: [aes_block_length]u8 = undefined;
                for (&y1_0, x2_0, z1_2) |*p, x, z| {
                    p.* = x ^ z;
                }

                // X1_0 = E^{-1}(Y1_0)
                var x1_0: [aes_block_length]u8 = undefined;
                state.ks1_dec.decrypt(&x1_0, &y1_0);

                // IV1 = X1_0 ⊕ Y1_0 ⊕ L1
                var iv1: [aes_block_length]u8 = undefined;
                for (&iv1, x1_0, y1_0, state.l1) |*p, x, y, l| {
                    p.* = x ^ y ^ l;
                }

                // XCTR^{-1} round 1: R -> M* (in-place in dst)
                const m_star_out = dst[aes_block_length..];
                xctr(state.ks1_enc, m_star_out, r_slice, iv1);

                // First hash: Z1 = H1(T, M*)
                poly1 = poly1_after_tweak;
                const z1 = absorb(&poly1, m_star_out);

                // M0 = X1_0 ⊕ Z1
                const m0_out = dst[0..aes_block_length];
                for (m0_out, x1_0, z1) |*p, x, z| {
                    p.* = x ^ z;
                }
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

        fn xctr(ks_enc: AesEncryptCtx, dst: []u8, src: []const u8, z: [aes_block_length]u8) void {
            const batch = Aes.block.parallel.optimal_parallel_blocks;
            const block_length_batch = aes_block_length * batch;
            var counter_bytes_batch: [block_length_batch]u8 = undefined;
            var counter: u64 = 1;
            var i: usize = 0;

            if (src.len > block_length_batch) {
                var z_batch: [counter_bytes_batch.len]u8 = undefined;
                inline for (0..batch) |j| {
                    z_batch[j * aes_block_length ..][0..aes_block_length].* = z;
                }
                while (i + block_length_batch <= src.len) : (i += block_length_batch) {
                    inline for (0..batch) |j| {
                        mem.writeInt(u64, counter_bytes_batch[aes_block_length * j ..][0..8], counter, .little);
                        @memset(counter_bytes_batch[aes_block_length * j ..][8..], 0);
                        counter += 1;
                    }
                    for (&counter_bytes_batch, z_batch) |*p, x| {
                        p.* ^= x;
                    }
                    ks_enc.encryptWide(batch, &counter_bytes_batch, &counter_bytes_batch);
                    for (dst[i..][0..block_length_batch], src[i..][0..block_length_batch], counter_bytes_batch) |*d, s, c| {
                        d.* = s ^ c;
                    }
                }
            }

            const counter_bytes = counter_bytes_batch[0..aes_block_length];

            while (i + aes_block_length <= src.len) : (i += aes_block_length) {
                mem.writeInt(u64, counter_bytes[0..8], counter, .little);
                @memset(counter_bytes[8..], 0);
                counter += 1;
                for (counter_bytes, z) |*p, x| {
                    p.* ^= x;
                }
                ks_enc.encrypt(counter_bytes, counter_bytes);
                for (dst[i..][0..aes_block_length], src[i..][0..aes_block_length], counter_bytes) |*d, s, c| {
                    d.* = s ^ c;
                }
            }

            const left = src.len - i;
            if (left > 0) {
                mem.writeInt(u64, counter_bytes[0..8], counter, .little);
                @memset(counter_bytes[8..], 0);
                for (counter_bytes, z) |*p, x| {
                    p.* ^= x;
                }
                ks_enc.encrypt(counter_bytes, counter_bytes);
                for (dst[i..], src[i..], counter_bytes[0..left]) |*d, s, c| {
                    d.* = s ^ c;
                }
            }
        }
    };
}

test "CHCTR2-128 encrypt/decrypt round-trip" {
    const key = [_]u8{0} ** 32; // 32 bytes for two AES-128 keys
    var state = Chctr2_128.init(key);

    const plaintext = "Hello, CHCTR2 World!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const tweak = "test tweak";

    try state.encrypt(&ciphertext, plaintext, tweak);
    try state.decrypt(&decrypted, &ciphertext, tweak);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "CHCTR2-256 encrypt/decrypt round-trip" {
    const key = [_]u8{0} ** 64; // 64 bytes for two AES-256 keys
    var state = Chctr2_256.init(key);

    const plaintext = "Hello, CHCTR2-256 World!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const tweak = "test tweak 256";

    try state.encrypt(&ciphertext, plaintext, tweak);
    try state.decrypt(&decrypted, &ciphertext, tweak);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "CHCTR2-128 minimum block size" {
    const key = [_]u8{0} ** 32;
    var state = Chctr2_128.init(key);

    // Exactly 16 bytes (minimum)
    const plaintext = [_]u8{0x42} ** 16;
    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    try state.encrypt(&ciphertext, &plaintext, "");
    try state.decrypt(&decrypted, &ciphertext, "");

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "CHCTR2-128 input too short" {
    const key = [_]u8{0} ** 32;
    var state = Chctr2_128.init(key);

    const plaintext = [_]u8{0x42} ** 15; // Too short
    var ciphertext: [15]u8 = undefined;

    try std.testing.expectError(error.InputTooShort, state.encrypt(&ciphertext, &plaintext, ""));
}

test "CHCTR2-128 different tweaks produce different ciphertexts" {
    const key = [_]u8{0} ** 32;
    var state = Chctr2_128.init(key);

    const plaintext = [_]u8{0x42} ** 32;
    var ciphertext1: [32]u8 = undefined;
    var ciphertext2: [32]u8 = undefined;

    try state.encrypt(&ciphertext1, &plaintext, "tweak1");
    try state.encrypt(&ciphertext2, &plaintext, "tweak2");

    try std.testing.expect(!std.mem.eql(u8, &ciphertext1, &ciphertext2));
}

test "CHCTR2-128 initSplit" {
    const key1 = [_]u8{0x01} ** 16;
    const key2 = [_]u8{0x02} ** 16;
    var state = Chctr2_128.initSplit(key1, key2);

    const plaintext = "Test split key init";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    try state.encrypt(&ciphertext, plaintext, "tweak");
    try state.decrypt(&decrypted, &ciphertext, "tweak");

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "CHCTR2-128 large message" {
    const key = [_]u8{0} ** 32;
    var state = Chctr2_128.init(key);

    // 1KB message
    const plaintext = [_]u8{0xAB} ** 1024;
    var ciphertext: [1024]u8 = undefined;
    var decrypted: [1024]u8 = undefined;

    try state.encrypt(&ciphertext, &plaintext, "large tweak");
    try state.decrypt(&decrypted, &ciphertext, "large tweak");

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
