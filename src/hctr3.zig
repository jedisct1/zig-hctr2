const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const assert = std.debug.assert;
const Polyval = @import("polyval.zig").Polyval(1);
const absorb = @import("hctr2.zig").absorb;
const lengthBlock = @import("hctr2.zig").lengthBlock;
const loadBlock = @import("block.zig").loadBlock;
const storeBlock = @import("block.zig").storeBlock;

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
    const hash_digest_length = Hash.digest_length;

    return struct {
        const State = @This();

        ks_enc: AesEncryptCtx,
        ks_dec: AesDecryptCtx,
        ke_enc: AesEncryptCtx,
        ke_dec: AesDecryptCtx,
        poly: Polyval,
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

            const block_bytes = lengthBlock(tweak.len, n.len);
            var poly = state.poly.hasher();
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

        fn elk(state: *const State, dst: []u8, src: []const u8, seed: [aes_block_length]u8) void {
            const batch = Aes.block.parallel.optimal_parallel_blocks;
            const batch_length = aes_block_length * batch;
            var lfsr = loadBlock(&seed);
            var states: [batch_length]u8 = undefined;
            var i: usize = 0;

            while (i + batch_length <= src.len) : (i += batch_length) {
                inline for (0..batch) |j| {
                    storeBlock(states[j * aes_block_length ..][0..aes_block_length], lfsr);
                    lfsr = lfsrStep(lfsr);
                }
                state.ke_enc.xorWide(batch, dst[i..][0..batch_length], src[i..][0..batch_length], states);
            }

            while (i < src.len) : (i += aes_block_length) {
                var keystream: [aes_block_length]u8 = undefined;
                storeBlock(&keystream, lfsr);
                lfsr = lfsrStep(lfsr);
                state.ke_enc.encrypt(&keystream, &keystream);
                const left = @min(aes_block_length, src.len - i);
                for (dst[i..][0..left], src[i..][0..left], keystream[0..left]) |*d, x, k| {
                    d.* = x ^ k;
                }
            }
        }
    };
}

/// The LFSR that HCTR3 uses as a counter: multiplication by x modulo x^128 + x^7 + x^2 + x + 1.
pub fn lfsrStep(v: u128) u128 {
    return (v << 1) ^ (0x87 & (0 -% (v >> 127)));
}
