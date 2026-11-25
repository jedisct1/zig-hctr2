const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const assert = std.debug.assert;
const hctr2 = @import("hctr2.zig");
const Polyval = @import("polyval.zig").Polyval;
const absorb = hctr2.absorb;

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
/// Each block costs 2 AES calls and 4 field multiplications.
///
/// You get about 85 bits of multi-user security instead of 64, with no limits on how tweaks are used.
/// That assumes the data is spread over many users.
/// A single user encrypting long messages gets a bit less, around 83 bits with 4 KiB sectors.
pub fn Chctr2(comptime Aes: anytype) type {
    const Hctr2 = hctr2.Hctr2(Aes);
    const aes_block_length = Aes.block.block_length;

    return struct {
        const State = @This();

        first: Hctr2,
        second: Hctr2,

        /// Both hash keys, for the hash in the middle, which runs under each of them.
        poly12: Polyval(2),

        /// CHCTR2 doesn't produce tags.
        pub const tag_length = 0;

        /// CHCTR2 takes a tweak instead of a nonce.
        pub const nonce_length = 0;

        /// The two AES keys, one after the other.
        pub const key_length = 2 * single_key_length;

        pub const single_key_length = Aes.key_bits / 8;

        pub const block_length = aes_block_length;

        pub fn init(key: [key_length]u8) State {
            return initSplit(key[0..single_key_length].*, key[single_key_length..].*);
        }

        /// Same as `init`, with the keys of the two HCTR2 passes given separately.
        pub fn initSplit(key1: [single_key_length]u8, key2: [single_key_length]u8) State {
            const first = Hctr2.init(key1);
            const second = Hctr2.init(key2);
            var hash_keys: [2][aes_block_length]u8 = @splat(@splat(0));
            first.ks_enc.encrypt(&hash_keys[0], &hash_keys[0]);
            second.ks_enc.encrypt(&hash_keys[1], &hash_keys[1]);
            return .{ .first = first, .second = second, .poly12 = .init(hash_keys) };
        }

        const Direction = enum { encrypt, decrypt };

        /// Encrypts `plaintext` into `ciphertext`, which must have the same length and can be the same buffer.
        ///
        /// Returns `error.InputTooShort` if the input is shorter than one block.
        pub fn encrypt(state: *State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            try state.chctr2(ciphertext, plaintext, tweak, .encrypt);
        }

        /// Decrypts `ciphertext` into `plaintext`, which must have the same length and can be the same buffer.
        ///
        /// Returns `error.InputTooShort` if the input is shorter than one block.
        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            try state.chctr2(plaintext, ciphertext, tweak, .decrypt);
        }

        // HCTR2 under the first key, then under the second key, with the hash in the middle done once for both keys.
        // That middle step XORs the two hashes, and a single hash keyed with H1 XOR H2 would give a different result.
        fn chctr2(state: *const State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
            assert(dst.len == src.len);
            if (src.len < aes_block_length) {
                return error.InputTooShort;
            }

            // Decryption undoes the second pass first.
            const pass1, const pass2 = if (direction == .encrypt) .{ &state.first, &state.second } else .{ &state.second, &state.first };

            const head = src[0..aes_block_length].*;
            const src_tail = src[aes_block_length..];
            const tail = dst[aes_block_length..];

            const length_block = hctr2.lengthBlock(tweak.len, src_tail.len);
            const zeros: [aes_block_length]u8 = @splat(0);
            const tweak_pad = zeros[0 .. (0 -% tweak.len) % aes_block_length];
            var poly1 = pass1.poly.hasher();
            var poly2 = pass2.poly.hasher();
            var poly12 = state.poly12.hasher();
            inline for (.{ &poly1, &poly2, &poly12 }) |poly| {
                poly.update(&length_block);
                poly.update(tweak);
                poly.update(tweak_pad);
            }

            const x1 = xor(head, absorb(&poly1, src_tail));
            const y1 = blockCipher(pass1, direction, x1);
            hctr2.xctr(Aes, &pass1.ks_enc, tail, src_tail, xor(xor(x1, y1), pass1.l));

            const middle = absorb(&poly12, tail);
            const x2 = xor(y1, xor(middle[0..aes_block_length].*, middle[aes_block_length..].*));
            const y2 = blockCipher(pass2, direction, x2);
            hctr2.xctr(Aes, &pass2.ks_enc, tail, tail, xor(xor(x2, y2), pass2.l));

            dst[0..aes_block_length].* = xor(y2, absorb(&poly2, tail));
        }

        fn blockCipher(pass: *const Hctr2, comptime direction: Direction, x: [aes_block_length]u8) [aes_block_length]u8 {
            var y: [aes_block_length]u8 = undefined;
            if (direction == .encrypt) {
                pass.ks_enc.encrypt(&y, &x);
            } else {
                pass.ks_dec.decrypt(&y, &x);
            }
            return y;
        }

        fn xor(a: [aes_block_length]u8, b: [aes_block_length]u8) [aes_block_length]u8 {
            var r = a;
            for (&r, b) |*p, x| p.* ^= x;
            return r;
        }
    };
}

fn sequence(comptime n: usize) [n]u8 {
    var bytes: [n]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i);
    return bytes;
}

fn expectCiphertext(cipher: anytype, tweak: []const u8, comptime hex: []const u8) !void {
    const len = hex.len / 2;
    var expected: [len]u8 = undefined;
    var output: [len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, hex);
    try cipher.encrypt(&output, &sequence(len), tweak);
    try std.testing.expectEqualSlices(u8, &expected, &output);
}

test "CHCTR2 is HCTR2 applied twice" {
    inline for (.{ aes.Aes128, aes.Aes256 }) |Aes| {
        const Cascade = Chctr2(Aes);
        const Single = hctr2.Hctr2(Aes);
        const key = sequence(Cascade.key_length);
        const key1 = key[0..Cascade.single_key_length].*;
        const key2 = key[Cascade.single_key_length..].*;

        var cascade = Cascade.initSplit(key1, key2);
        var first = Single.init(key1);
        var second = Single.init(key2);

        for ([_][]const u8{ "", "tweak", "a tweak longer than one block" }) |tweak| {
            inline for (.{ 16, 17, 32, 1023 }) |len| {
                const message = sequence(len);
                var middle: [len]u8 = undefined;
                var expected: [len]u8 = undefined;
                var output: [len]u8 = undefined;

                try first.encrypt(&middle, &message, tweak);
                try second.encrypt(&expected, &middle, tweak);
                try cascade.encrypt(&output, &message, tweak);
                try std.testing.expectEqualSlices(u8, &expected, &output);

                try cascade.decrypt(&output, &expected, tweak);
                try std.testing.expectEqualSlices(u8, &message, &output);
            }
        }
    }
}

test "CHCTR2 known answers" {
    // Expected values were computed separately, following the paper.
    var cipher128 = Chctr2_128.init(sequence(32));
    var cipher256 = Chctr2_256.init(sequence(64));

    try expectCiphertext(&cipher128, "", "2f4e9b98ee561c3cdc589fec85032854");
    try expectCiphertext(&cipher128, "tweak", "17bf924f79cf31d420d8989babe6f01562f05365cde3afeffd7f7f52075ec66332");
    try expectCiphertext(&cipher256, "tweak 256", "dea1f0fa322fd77c2219064ed27d585b2f21f302b85b85218586830825b08c5ae19ab21ac04108daf97850f0d294c307f8ab5f2bb48a88877750531b1261940380");
}

test "CHCTR2 rejects short input" {
    var cipher = Chctr2_128.init(@splat(0));
    const input: [15]u8 = @splat(0x42);
    var output: [15]u8 = undefined;

    try std.testing.expectError(error.InputTooShort, cipher.encrypt(&output, &input, ""));
}
