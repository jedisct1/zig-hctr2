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

/// A length-preserving wide-block tweakable cipher that's stronger than plain HCTR2.
///
/// It encrypts with HCTR2 under the first key, then again under the second key.
/// From "Beyond-Birthday-Bound Security with HCTR2", ASIACRYPT 2025.
///
/// The middle step XORs the hashes from both keys.
/// Don't replace that with one hash keyed with H1 XOR H2, the result would be different.
///
/// Each block costs 2 AES calls and 4 field multiplications.
///
/// You get about 85 bits of multi-user security instead of 64, with no limits on how tweaks are used.
/// That assumes the data is spread over many users.
/// A single user encrypting long messages gets a bit less, around 83 bits with 4 KiB sectors.
///
/// `Aes` selects the AES variant.
pub fn Chctr2(comptime Aes: anytype) type {
    const AesEncryptCtx = aes.AesEncryptCtx(Aes);
    const AesDecryptCtx = aes.AesDecryptCtx(Aes);
    const Block = Aes.block;

    const aes_block_length = Block.block_length;
    const hash_block_length = Polyval.block_length;

    return struct {
        const State = @This();

        ks1_enc: AesEncryptCtx,
        ks1_dec: AesDecryptCtx,
        h1: [Polyval.key_length]u8,
        l1: [aes_block_length]u8,

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
            const ks1_enc = Aes.initEnc(key1);
            const ks1_dec = AesDecryptCtx.initFromEnc(ks1_enc);

            var block_bytes1 = @as([aes_block_length]u8, @splat(0)) ++ [_]u8{1} ++ @as([aes_block_length - 1]u8, @splat(0));
            ks1_enc.encryptWide(2, &block_bytes1, &block_bytes1);
            const h1 = block_bytes1[0..aes_block_length].*;
            const l1 = block_bytes1[aes_block_length..].*;

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

        /// Same output as calling HCTR2 twice, but each key only hashes the tweak once.
        fn chctr2(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
            assert(dst.len == src.len);
            if (src.len < aes_block_length) {
                return error.InputTooShort;
            }

            const m0 = src[0..aes_block_length];
            const m_star = src[aes_block_length..];

            var block_bytes: [aes_block_length]u8 = @splat(0);
            const tweak_len_bits = @as(u128, tweak.len) * 8;
            const tweak_len_bytes = if (m_star.len % aes_block_length == 0) 2 * tweak_len_bits + 2 else 2 * tweak_len_bits + 3;
            mem.writeInt(u128, &block_bytes, tweak_len_bytes, .little);

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

            const poly1_after_tweak = poly1;
            const poly2_after_tweak = poly2;

            if (direction == .encrypt) {
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

fn sequence(comptime n: usize) [n]u8 {
    var bytes: [n]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i);
    return bytes;
}

fn expectCiphertext(cipher: anytype, comptime len: usize, tweak: []const u8, hex: []const u8) !void {
    var expected: [len]u8 = undefined;
    var output: [len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, hex);
    try cipher.encrypt(&output, &sequence(len), tweak);
    try std.testing.expectEqualSlices(u8, &expected, &output);
}

test "CHCTR2 is HCTR2 applied twice" {
    const hctr2 = @import("hctr2.zig");
    const message = sequence(1023);

    inline for (.{
        .{ Chctr2_128, hctr2.Hctr2_128 },
        .{ Chctr2_256, hctr2.Hctr2_256 },
    }) |variant| {
        const Cascade, const Single = variant;
        const key = sequence(Cascade.key_length);
        const key1 = key[0..Cascade.single_key_length].*;
        const key2 = key[Cascade.single_key_length..].*;

        var cascade = Cascade.initSplit(key1, key2);
        var first = Single.init(key1);
        var second = Single.init(key2);

        for ([_][]const u8{ "", "tweak", "a tweak longer than one block" }) |tweak| {
            for ([_]usize{ 16, 17, 32, 1023 }) |len| {
                var middle: [1023]u8 = undefined;
                var expected: [1023]u8 = undefined;
                var output: [1023]u8 = undefined;
                var decrypted: [1023]u8 = undefined;

                try first.encrypt(middle[0..len], message[0..len], tweak);
                try second.encrypt(expected[0..len], middle[0..len], tweak);
                try cascade.encrypt(output[0..len], message[0..len], tweak);
                try std.testing.expectEqualSlices(u8, expected[0..len], output[0..len]);

                try cascade.decrypt(decrypted[0..len], output[0..len], tweak);
                try std.testing.expectEqualSlices(u8, message[0..len], decrypted[0..len]);
            }
        }
    }
}

test "CHCTR2 known answers" {
    // Expected values were computed independently from the paper.
    var cipher128 = Chctr2_128.init(sequence(32));
    var cipher256 = Chctr2_256.init(sequence(64));

    try expectCiphertext(&cipher128, 16, "", "2f4e9b98ee561c3cdc589fec85032854");
    try expectCiphertext(&cipher128, 33, "tweak", "17bf924f79cf31d420d8989babe6f01562f05365cde3afeffd7f7f52075ec66332");
    try expectCiphertext(&cipher256, 65, "tweak 256", "dea1f0fa322fd77c2219064ed27d585b2f21f302b85b85218586830825b08c5ae19ab21ac04108daf97850f0d294c307f8ab5f2bb48a88877750531b1261940380");
}

test "CHCTR2 rejects short input" {
    var cipher = Chctr2_128.init(@splat(0));
    const input: [15]u8 = @splat(0x42);
    var output: [15]u8 = undefined;

    try std.testing.expectError(error.InputTooShort, cipher.encrypt(&output, &input, ""));
}
