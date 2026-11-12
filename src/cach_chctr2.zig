const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const chctr2 = @import("chctr2.zig");

/// CACH-CHCTR2 with AES-128 and a 32-byte tag.
pub const CachChctr2_128 = CachChctr2(aes.Aes128, 32);

/// CACH-CHCTR2 with AES-256 and a 32-byte tag.
pub const CachChctr2_256 = CachChctr2(aes.Aes256, 32);

/// A key-committing authenticated cipher, built from CHCTR2 with the CACH transform.
/// From "More Keys, Less Commitment: Key-Committing Attacks on BBB Accordions via Encode-then-Encipher and a Key-Committing Transform".
///
/// It needs a single AES key, and the ciphertext is as long as the message, plus a separate tag.
///
/// The tag commits to the key.
/// An attacker cannot find a ciphertext and a tag that are valid under two different keys.
/// A tag of `tag_bytes` bytes gives about `4 * tag_bytes` bits of key-committing security.
///
/// Put the nonce and the associated data in the tweak, with an unambiguous encoding.
/// Reusing a tweak only reveals whether two messages are equal.
///
/// Messages must be at least 32 bytes long.
/// Each message costs one CHCTR2 call, five AES calls and one AES key schedule.
///
/// `tag_bytes` can be anything from 16 to 32.
pub fn CachChctr2(comptime Aes: anytype, comptime tag_bytes: usize) type {
    const AesEncryptCtx = aes.AesEncryptCtx(Aes);
    const Accordion = chctr2.Chctr2(Aes);

    const aes_block_length = Aes.block.block_length;
    const kdf_blocks = Accordion.key_length / aes_block_length;

    assert(tag_bytes >= aes_block_length and tag_bytes <= 2 * aes_block_length);

    return struct {
        const State = @This();

        ks_enc: AesEncryptCtx,
        accordion: Accordion,

        /// Authentication tag length in bytes.
        pub const tag_length = tag_bytes;

        /// Nonce length (0 - the tweak carries the nonce).
        pub const nonce_length = 0;

        /// Key length in bytes (a single AES key).
        pub const key_length = Aes.key_bits / 8;

        /// AES block length in bytes (always 16).
        pub const block_length = aes_block_length;

        /// Minimum message length in bytes.
        pub const min_message_length = 2 * aes_block_length;

        /// Initialize the cipher state from a single AES key.
        pub fn init(key: [key_length]u8) State {
            const ks_enc = Aes.initEnc(key);

            // The two low bits stay at zero, so these blocks never match the ones the tag encrypts.
            var derived: [Accordion.key_length]u8 = undefined;
            inline for (0..kdf_blocks) |i| {
                mem.writeInt(u128, derived[i * aes_block_length ..][0..aes_block_length], i << 2, .big);
            }
            ks_enc.encryptWide(kdf_blocks, &derived, &derived);

            return State{
                .ks_enc = ks_enc,
                .accordion = Accordion.init(derived),
            };
        }

        /// Encrypt `plaintext` into `ciphertext` and compute the tag.
        /// Both buffers have the same length, and they can be the same buffer.
        ///
        /// Returns `error.InputTooShort` if the message is shorter than `min_message_length`.
        pub fn encrypt(state: *State, ciphertext: []u8, tag: *[tag_length]u8, plaintext: []const u8, tweak: []const u8) !void {
            tag.* = try state.cach(ciphertext, plaintext, tweak, .encrypt);
        }

        /// Decrypt `ciphertext` into `plaintext` and verify the tag.
        /// Both buffers have the same length, and they can be the same buffer.
        ///
        /// Returns `error.InputTooShort` if the message is shorter than `min_message_length`.
        /// Returns `error.AuthenticationFailed` if the tag is wrong, and clears `plaintext`.
        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tag: [tag_length]u8, tweak: []const u8) !void {
            const expected_tag = try state.cach(plaintext, ciphertext, tweak, .decrypt);
            if (!crypto.timing_safe.eql([tag_length]u8, expected_tag, tag)) {
                crypto.secureZero(u8, plaintext);
                return error.AuthenticationFailed;
            }
        }

        const Direction = enum { encrypt, decrypt };

        fn cach(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) ![tag_length]u8 {
            assert(dst.len == src.len);
            if (src.len < min_message_length) {
                return error.InputTooShort;
            }

            // Copy the input first, because `dst` can be the same buffer as `src`.
            var s = src[0..min_message_length].*;
            switch (direction) {
                .encrypt => try state.accordion.encrypt(dst, src, tweak),
                .decrypt => try state.accordion.decrypt(dst, src, tweak),
            }
            for (&s, dst[0..min_message_length]) |*p, d| {
                p.* ^= d;
            }
            return state.ceth(s);
        }

        /// CEtH from the paper, a collision-resistant PRF that turns `s` into the tag.
        /// The second half of `s` picks a one-time key, and the first half is hashed under that key.
        /// The paper uses a few low bits of each half for domain separation, so these bits don't change the tag.
        fn ceth(state: *const State, s: [2 * aes_block_length]u8) [tag_length]u8 {
            const s1 = s[0..aes_block_length];
            const s2 = s[aes_block_length..];

            var cenc = s2.* ++ s2.* ++ s2.*;
            inline for (.{ 1, 2, 3 }) |domain| {
                const last = &cenc[domain * aes_block_length - 1];
                last.* = (last.* & 0xfc) | domain;
            }
            state.ks_enc.encryptWide(3, &cenc, &cenc);

            // CENC gives 32 bytes.
            // The bytes that the Hirose key doesn't use are padded with zeros to one block, and go into the tag.
            var key_material: [key_length + aes_block_length]u8 = @splat(0);
            const v1 = cenc[0..aes_block_length].*;
            for (key_material[0 .. 2 * aes_block_length], v1 ++ v1, cenc[aes_block_length..]) |*p, a, b| {
                p.* = a ^ b;
            }
            const hirose_key = key_material[0..key_length];
            const feed_forward = key_material[key_length..];

            var x = s1.* ++ s1.*;
            x[aes_block_length - 1] &= 0xf8;
            x[2 * aes_block_length - 1] = (x[2 * aes_block_length - 1] & 0xf8) | 0x04;

            var z: [2 * aes_block_length]u8 = undefined;
            Aes.initEnc(hirose_key.*).xorWide(2, &z, &x, x);
            for (z[0..aes_block_length], feed_forward) |*p, v| {
                p.* ^= v;
            }

            return z[0..tag_length].*;
        }
    };
}

fn sequence(comptime n: usize) [n]u8 {
    var bytes: [n]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i);
    return bytes;
}

fn expectVector(cipher: anytype, tweak: []const u8, comptime ciphertext_hex: []const u8, comptime tag_hex: []const u8) !void {
    const message = sequence(ciphertext_hex.len / 2);
    var expected: [message.len]u8 = undefined;
    var expected_tag: [tag_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, ciphertext_hex);
    _ = try std.fmt.hexToBytes(&expected_tag, tag_hex);

    var output: [message.len]u8 = undefined;
    var tag: [expected_tag.len]u8 = undefined;
    try cipher.encrypt(&output, &tag, &message, tweak);
    try std.testing.expectEqualSlices(u8, &expected, &output);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    try cipher.decrypt(&output, &output, tag, tweak);
    try std.testing.expectEqualSlices(u8, &message, &output);
}

test "CACH-CHCTR2 known answers" {
    // Computed with an independent Python implementation of the paper.
    var cipher128 = CachChctr2_128.init(sequence(16));
    var cipher256 = CachChctr2_256.init(sequence(32));
    var cipher256_short_tag = CachChctr2(aes.Aes256, 16).init(sequence(32));

    try expectVector(
        &cipher128,
        "",
        "c9b34805f981180bb490278842f7abfafaf1f46bd3b56e34d97366f2d1b87586",
        "d189ce8a553521bc68fcad4095f84110429fdd1b5b0e1ad774ae1dca727dc434",
    );
    try expectVector(
        &cipher128,
        "tweak",
        "0238a7b0151adb2436551a6c1551ed1a6a636c68aca6f8415777c3c8a190a2fbe2",
        "4faa7c99980f97120a4dd9422c4c50df9818fc0664aa6a8a522773817a342390",
    );
    try expectVector(
        &cipher256,
        "tweak",
        "ad9c7c3b3a7c0b925c4534c4aae7e0e15db44fdd881eeac825608e6bfc5c6cd7494e00599e31597a529a93ecfe9e2316",
        "592df8fae784ff1312e230b6c3101877c9b91bb4fc418e53908b8905f28c924c",
    );
    // A 16-byte tag is the first half of the 32-byte tag.
    try expectVector(
        &cipher256_short_tag,
        "tweak",
        "ad9c7c3b3a7c0b925c4534c4aae7e0e15db44fdd881eeac825608e6bfc5c6cd7494e00599e31597a529a93ecfe9e2316",
        "592df8fae784ff1312e230b6c3101877",
    );
    try expectVector(
        &cipher256,
        "a tweak longer than one block",
        "64b1a9d9db813b15d88341051d3df82e02d436b66d2d408fb106812ac9607e191da3c2e0b70309280161db99197ff5aa5c985ad5fb1c288f57707ba94864d6978cd7df4e9e3b7159112fd80aefebdf5ba3f0efaccf385c0cb3198fef3171871f018b631b",
        "eb9c0b19138952d1a3e08bc789d6fd97abd2081b8a672e36a930f0630d3d7b44",
    );
}

test "CACH-CHCTR2 rejects forgeries" {
    inline for (.{ CachChctr2_128, CachChctr2(aes.Aes256, 16) }) |Cach| {
        var cipher = Cach.init(sequence(Cach.key_length));
        var ciphertext: [48]u8 = undefined;
        var tag: [Cach.tag_length]u8 = undefined;
        try cipher.encrypt(&ciphertext, &tag, &sequence(48), "tweak");

        var output: [48]u8 = undefined;
        var bad_tag = tag;
        bad_tag[Cach.tag_length - 1] ^= 1;
        try std.testing.expectError(error.AuthenticationFailed, cipher.decrypt(&output, &ciphertext, bad_tag, "tweak"));
        try std.testing.expect(mem.allEqual(u8, &output, 0));

        try std.testing.expectError(error.AuthenticationFailed, cipher.decrypt(&output, &ciphertext, tag, "tweaj"));

        // The last byte doesn't go into the tag directly, but a change must still be detected.
        var bad_ciphertext = ciphertext;
        bad_ciphertext[bad_ciphertext.len - 1] ^= 1;
        try std.testing.expectError(error.AuthenticationFailed, cipher.decrypt(&output, &bad_ciphertext, tag, "tweak"));

        var other = Cach.init(@splat(0));
        try std.testing.expectError(error.AuthenticationFailed, other.decrypt(&output, &ciphertext, tag, "tweak"));
    }
}

test "CACH-CHCTR2 rejects short input" {
    const Cach = CachChctr2_128;
    var cipher = Cach.init(@splat(0));
    const input: [Cach.min_message_length - 1]u8 = @splat(0x42);
    var output: [input.len]u8 = undefined;
    var tag: [Cach.tag_length]u8 = undefined;

    try std.testing.expectError(error.InputTooShort, cipher.encrypt(&output, &tag, &input, ""));
    try std.testing.expectError(error.InputTooShort, cipher.decrypt(&output, &input, tag, ""));
}
