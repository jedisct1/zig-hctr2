const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = crypto.onetimeauth.Polyval;

/// HCTR2 with AES-128 encryption.
pub const Hctr2_128 = Hctr2(aes.Aes128);

/// HCTR2 with AES-256 encryption.
pub const Hctr2_256 = Hctr2(aes.Aes256);

/// HCTR2 (Hash-CTR-Hash) is a length-preserving wide-block tweakable cipher.
///
/// HCTR2 provides full-block diffusion: any change to plaintext affects the entire ciphertext.
/// It requires no nonce or authentication tag, making it suitable for constrained environments.
///
/// Construction uses:
/// - Single encryption key
/// - Polyval universal hash function
/// - XCTR mode for wide-block encryption (counter-based)
///
/// Security properties:
/// - Ciphertext length equals plaintext length (no expansion)
/// - Requires unique (key, tweak) pairs for security
/// - No authentication - consider AEAD if integrity protection is needed
/// - Minimum message length: 16 bytes (one AES block)
///
/// Type parameters:
/// - `Aes`: AES variant (Aes128 or Aes256)
pub fn Hctr2(comptime Aes: anytype) type {
    const AesEncryptCtx = aes.AesEncryptCtx(Aes);
    const AesDecryptCtx = aes.AesDecryptCtx(Aes);
    const Block = Aes.block;

    const aes_block_length = Block.block_length;
    const hash_block_length = Polyval.block_length;

    return struct {
        const State = @This();

        ks_enc: AesEncryptCtx,
        ks_dec: AesDecryptCtx,
        poly: Polyval,
        h: [Polyval.key_length]u8,
        l: [aes_block_length]u8,

        /// Authentication tag length (0 - HCTR2 is unauthenticated).
        pub const tag_length = 0;

        /// Nonce length (0 - HCTR2 uses tweaks instead).
        pub const nonce_length = 0;

        /// Encryption key length in bytes (16 for AES-128, 32 for AES-256).
        pub const key_length = Aes.key_bits / 8;

        /// AES block length in bytes (always 16).
        pub const block_length = aes_block_length;

        /// Initialize HCTR2 cipher state from an encryption key.
        ///
        /// Parameters:
        /// - `key`: Encryption key (16 bytes for AES-128, 32 bytes for AES-256)
        ///
        /// Returns: Initialized cipher state ready for encryption/decryption operations.
        pub fn init(key: [Aes.key_bits / 8]u8) State {
            const ks_enc = Aes.initEnc(key);
            const ks_dec = AesDecryptCtx.initFromEnc(ks_enc);

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

        /// Encrypt plaintext to ciphertext using HCTR2.
        ///
        /// Parameters:
        /// - `state`: Initialized cipher state
        /// - `ciphertext`: Output buffer (must be same length as plaintext)
        /// - `plaintext`: Input data to encrypt (minimum 16 bytes)
        /// - `tweak`: Tweak value for domain separation (can be empty, but must be unique per message with same key)
        ///
        /// Returns: `error.InputTooShort` if plaintext is less than 16 bytes.
        ///
        /// Security: Never reuse the same (key, tweak) pair for different messages.
        pub fn encrypt(state: *State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            try state.hctr2(ciphertext, plaintext, tweak, .encrypt);
        }

        /// Decrypt ciphertext to plaintext using HCTR2.
        ///
        /// Parameters:
        /// - `state`: Initialized cipher state
        /// - `plaintext`: Output buffer (must be same length as ciphertext)
        /// - `ciphertext`: Input data to decrypt (minimum 16 bytes)
        /// - `tweak`: Tweak value used during encryption
        ///
        /// Returns: `error.InputTooShort` if ciphertext is less than 16 bytes.
        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            try state.hctr2(plaintext, ciphertext, tweak, .decrypt);
        }

        fn hctr2(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
            assert(dst.len == src.len);
            if (src.len < aes_block_length) {
                return error.InputTooShort;
            }
            const m = src[0..aes_block_length];
            const n = src[aes_block_length..];

            var block_bytes: [aes_block_length]u8 = @splat(0);
            const tweak_len_bits = tweak.len * 8;
            const tweak_len_bytes = if (n.len % aes_block_length == 0) 2 * tweak_len_bits + 2 else 2 * tweak_len_bits + 3;
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
            state.xctr(v, n, s);

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

        fn xctr(state: *const State, dst: []u8, src: []const u8, z: [aes_block_length]u8) void {
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
                    state.ks_enc.encryptWide(batch, &counter_bytes_batch, &counter_bytes_batch);
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
                state.ks_enc.encrypt(counter_bytes, counter_bytes);
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
                state.ks_enc.encrypt(counter_bytes, counter_bytes);
                for (dst[i..], src[i..], counter_bytes[0..left]) |*d, s, c| {
                    d.* = s ^ c;
                }
            }
        }
    };
}
