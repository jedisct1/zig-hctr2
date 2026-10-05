const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = crypto.onetimeauth.Polyval;

/// HCTR3 instantiated with AES-128 and SHA-256 tweak processing.
pub const Hctr3_128 = Hctr3(aes.Aes128, crypto.hash.sha2.Sha256);

/// HCTR3 instantiated with AES-256 and SHA-256 tweak processing.
pub const Hctr3_256 = Hctr3(aes.Aes256, crypto.hash.sha2.Sha256);

/// A length-preserving wide-block tweakable cipher with hashed tweaks.
///
/// Do not encrypt different messages with the same key and tweak.
/// HCTR3 does not authenticate ciphertexts; use an AEAD when integrity is required.
/// Each input must contain at least one AES block.
///
/// `Aes` selects the AES variant.
/// `Hash` hashes tweaks before they enter the construction.
pub fn Hctr3(comptime Aes: anytype, comptime Hash: anytype) type {
    const AesEncryptCtx = aes.AesEncryptCtx(Aes);
    const AesDecryptCtx = aes.AesDecryptCtx(Aes);
    const Block = Aes.block;

    const aes_block_length = Block.block_length;
    const hash_block_length = Polyval.block_length;
    const hash_digest_length = Hash.digest_length;

    return struct {
        const State = @This();

        ks_enc: AesEncryptCtx,
        ks_dec: AesDecryptCtx,
        ke_enc: AesEncryptCtx,
        ke_dec: AesDecryptCtx,
        poly: Polyval,
        h: [Polyval.key_length]u8,
        l: [aes_block_length]u8,

        /// HCTR3 does not produce authentication tags.
        pub const tag_length = 0;

        /// HCTR3 uses caller-supplied tweaks rather than nonces.
        pub const nonce_length = 0;

        /// Length of an AES key for this instantiation.
        pub const key_length = Aes.key_bits / 8;

        /// AES block length.
        pub const block_length = aes_block_length;

        /// Creates a cipher state and derives its internal subkeys from `key`.
        pub fn init(key: [Aes.key_bits / 8]u8) State {
            const ks_enc = Aes.initEnc(key);
            const ks_dec = AesDecryptCtx.initFromEnc(ks_enc);

            var ke_bytes: [aes_block_length]u8 = @splat(0);
            ks_enc.encrypt(&ke_bytes, &ke_bytes);

            var ke_key: [key_length]u8 = undefined;
            if (key_length <= aes_block_length) {
                @memcpy(&ke_key, ke_bytes[0..key_length]);
            } else {
                @memcpy(ke_key[0..aes_block_length], &ke_bytes);
                var extra_block: [aes_block_length]u8 = @splat(1);
                ks_enc.encrypt(&extra_block, &extra_block);
                @memcpy(ke_key[aes_block_length..], extra_block[0..(key_length - aes_block_length)]);
            }

            const ke_enc = Aes.initEnc(ke_key);
            const ke_dec = AesDecryptCtx.initFromEnc(ke_enc);

            var kh_bytes: [aes_block_length]u8 = @splat(0);
            ke_enc.encrypt(&kh_bytes, &kh_bytes);

            var l_bytes: [aes_block_length]u8 = @as([aes_block_length - 1]u8, @splat(0)) ++ [_]u8{1};
            ke_enc.encrypt(&l_bytes, &l_bytes);

            const poly = Polyval.init(&kh_bytes);

            return State{
                .ks_enc = ks_enc,
                .ks_dec = ks_dec,
                .ke_enc = ke_enc,
                .ke_dec = ke_dec,
                .poly = poly,
                .h = kh_bytes,
                .l = l_bytes,
            };
        }

        const Direction = enum { encrypt, decrypt };

        /// Encrypts `plaintext` with `tweak` into `ciphertext`.
        ///
        /// The buffers must have equal length, and plaintext must be at least one block.
        /// Returns `error.InputTooShort` otherwise.
        /// Never reuse a key and tweak pair for different messages.
        pub fn encrypt(state: *State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            try state.hctr3(ciphertext, plaintext, tweak, .encrypt);
        }

        /// Decrypts `ciphertext` with its original `tweak` into `plaintext`.
        ///
        /// The buffers must have equal length, and ciphertext must be at least one block.
        /// Returns `error.InputTooShort` otherwise.
        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            try state.hctr3(plaintext, ciphertext, tweak, .decrypt);
        }

        fn hctr3(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
            assert(dst.len == src.len);
            if (src.len < aes_block_length) {
                return error.InputTooShort;
            }
            const m = src[0..aes_block_length];
            const n = src[aes_block_length..];

            var t: [aes_block_length]u8 = undefined;
            var hasher = Hash.init(.{});
            hasher.update(tweak);
            var hash_out: [hash_digest_length]u8 = undefined;
            hasher.final(&hash_out);

            if (hash_digest_length >= aes_block_length) {
                @memcpy(&t, hash_out[0..aes_block_length]);
            } else {
                @memcpy(t[0..hash_digest_length], &hash_out);
                @memset(t[hash_digest_length..], 0);
            }

            var block_bytes: [aes_block_length]u8 = @splat(0);
            const tweak_len_bits = @as(u128, tweak.len) * 8;
            const tweak_len_bytes = if (n.len % aes_block_length == 0) 2 * tweak_len_bits + 2 else 2 * tweak_len_bits + 3;
            mem.writeInt(u128, &block_bytes, tweak_len_bytes, .little);
            var poly = state.poly;
            poly.update(&block_bytes);

            poly.update(&t);

            const poly_after_tweak = poly;

            const hh = absorb(&poly, n);
            var mm = hh;
            for (&mm, m) |*p, x| {
                p.* ^= x;
            }

            var uu: [aes_block_length]u8 = undefined;
            if (direction == .encrypt) {
                state.ks_enc.encrypt(&uu, &mm);
            } else {
                state.ks_dec.decrypt(&uu, &mm);
            }

            var s = mm;
            for (&s, uu, state.l) |*p, x, y| {
                p.* ^= x ^ y;
            }

            const u = dst[0..aes_block_length];
            const v = dst[aes_block_length..];
            state.elk(v, n, s);

            poly = poly_after_tweak;
            const hh2 = absorb(&poly, v);
            for (u, uu, hh2) |*p, x, y| {
                p.* = x ^ y;
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

        fn elk(state: *const State, dst: []u8, src: []const u8, seed: [aes_block_length]u8) void {
            const batch = Aes.block.parallel.optimal_parallel_blocks;
            const block_length_batch = aes_block_length * batch;
            var counter_bytes_batch: [block_length_batch]u8 = undefined;
            var lfsr_state = seed;
            var i: usize = 0;

            if (src.len > block_length_batch) {
                while (i + block_length_batch <= src.len) : (i += block_length_batch) {
                    inline for (0..batch) |j| {
                        @memcpy(counter_bytes_batch[aes_block_length * j ..][0..aes_block_length], &lfsr_state);
                        lfsr_state = lfsr_next(lfsr_state);
                    }
                    state.ke_enc.encryptWide(batch, &counter_bytes_batch, &counter_bytes_batch);
                    for (dst[i..][0..block_length_batch], src[i..][0..block_length_batch], counter_bytes_batch) |*d, s, c| {
                        d.* = s ^ c;
                    }
                }
            }

            const counter_bytes = counter_bytes_batch[0..aes_block_length];

            while (i + aes_block_length <= src.len) : (i += aes_block_length) {
                @memcpy(counter_bytes, &lfsr_state);
                lfsr_state = lfsr_next(lfsr_state);
                state.ke_enc.encrypt(counter_bytes, counter_bytes);
                for (dst[i..][0..aes_block_length], src[i..][0..aes_block_length], counter_bytes) |*d, s, c| {
                    d.* = s ^ c;
                }
            }

            const left = src.len - i;
            if (left > 0) {
                @memcpy(counter_bytes, &lfsr_state);
                state.ke_enc.encrypt(counter_bytes, counter_bytes);
                for (dst[i..], src[i..], counter_bytes[0..left]) |*d, s, c| {
                    d.* = s ^ c;
                }
            }
        }

        /// Advances an LFSR state without data-dependent control flow.
        ///
        /// AES-128 uses x^128 + x^7 + x^2 + x + 1.
        /// AES-256 uses x^256 + x^254 + x^251 + x^246 + 1.
        pub fn lfsr_next(state: [aes_block_length]u8) [aes_block_length]u8 {
            var result = state;

            if (aes_block_length == 16) {
                const msb = result[15] >> 7;
                const mask = -%msb;

                var carry: u8 = 0;
                for (&result) |*byte| {
                    const new_carry = (byte.* & 0x80) >> 7;
                    byte.* = (byte.* << 1) | carry;
                    carry = new_carry;
                }

                result[0] ^= 0x87 & mask;
            } else if (aes_block_length == 32) {
                const msb = result[31] >> 7;
                const mask = -%msb;

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
            }

            return result;
        }
    };
}
