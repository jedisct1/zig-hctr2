const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = @import("polyval.zig").Polyval(1);

/// HCTR2 instantiated with AES-128.
pub const Hctr2_128 = Hctr2(aes.Aes128);

/// HCTR2 instantiated with AES-256.
pub const Hctr2_256 = Hctr2(aes.Aes256);

/// A length-preserving wide-block tweakable cipher.
///
/// Do not encrypt different messages with the same key and tweak.
/// HCTR2 does not authenticate ciphertexts; use an AEAD when integrity is required.
/// Each input must contain at least one AES block.
///
/// `Aes` selects the AES variant.
pub fn Hctr2(comptime Aes: anytype) type {
    const AesEncryptCtx = aes.AesEncryptCtx(Aes);
    const AesDecryptCtx = aes.AesDecryptCtx(Aes);
    const Block = Aes.block;

    const aes_block_length = Block.block_length;
    const hash_block_length = 16;

    return struct {
        const State = @This();

        ks_enc: AesEncryptCtx,
        ks_dec: AesDecryptCtx,
        poly: Polyval,
        l: [aes_block_length]u8,

        /// HCTR2 does not produce authentication tags.
        pub const tag_length = 0;

        /// HCTR2 uses caller-supplied tweaks rather than nonces.
        pub const nonce_length = 0;

        /// Length of an AES key for this instantiation.
        pub const key_length = Aes.key_bits / 8;

        /// AES block length.
        pub const block_length = aes_block_length;

        /// Creates a cipher state for `key`.
        pub fn init(key: [Aes.key_bits / 8]u8) State {
            const ks_enc = Aes.initEnc(key);
            const ks_dec = AesDecryptCtx.initFromEnc(ks_enc);

            var block_bytes = @as([aes_block_length]u8, @splat(0)) ++ [_]u8{1} ++ @as([aes_block_length - 1]u8, @splat(0));
            ks_enc.encryptWide(2, &block_bytes, &block_bytes);

            return State{
                .ks_enc = ks_enc,
                .ks_dec = ks_dec,
                .poly = .init(.{block_bytes[0..aes_block_length].*}),
                .l = block_bytes[aes_block_length..].*,
            };
        }

        const Direction = enum { encrypt, decrypt };

        /// Encrypts `plaintext` with `tweak` into `ciphertext`.
        ///
        /// The buffers must have equal length, and plaintext must be at least one block.
        /// Returns `error.InputTooShort` otherwise.
        /// Never reuse a key and tweak pair for different messages.
        pub fn encrypt(state: *State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            try state.hctr2(ciphertext, plaintext, tweak, .encrypt);
        }

        /// Decrypts `ciphertext` with its original `tweak` into `plaintext`.
        ///
        /// The buffers must have equal length, and ciphertext must be at least one block.
        /// Returns `error.InputTooShort` otherwise.
        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            try state.hctr2(plaintext, ciphertext, tweak, .decrypt);
        }

        fn hctr2(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
            assert(dst.len == src.len);
            if (src.len < aes_block_length) {
                return error.InputTooShort;
            }
            const m = src[0..aes_block_length].*;
            const n = src[aes_block_length..];

            const block_bytes = lengthBlock(tweak.len, n.len);
            var poly = state.poly.hasher();
            poly.update(&block_bytes);

            poly.update(tweak);
            const zeros: [hash_block_length]u8 = @splat(0);
            poly.update(zeros[0 .. (0 -% tweak.len) % hash_block_length]);

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
            xctr(Aes, &state.ks_enc, v, n, s);

            poly = poly_after_tweak;
            const hh2 = absorb(&poly, v);
            for (u, uu, hh2) |*p, x, y| {
                p.* = x ^ y;
            }
        }
    };
}

/// The first block that HCTR2 hashes, which encodes the tweak length and whether the message ends with a partial block.
pub fn lengthBlock(tweak_len: usize, msg_len: usize) [16]u8 {
    var out: [16]u8 = undefined;
    mem.writeInt(u128, &out, 2 * 8 * @as(u128, tweak_len) + 2 + @intFromBool(msg_len % 16 != 0), .little);
    return out;
}

/// Hashes `msg`, pads a partial last block with a 1 byte and zeros like HCTR2 does, and returns the hash.
pub fn absorb(hasher: anytype, msg: []const u8) @TypeOf(hasher.final()) {
    hasher.update(msg);
    const pad_len = (0 -% msg.len) % 16;
    if (pad_len > 0) {
        const pad = [_]u8{1} ++ @as([15]u8, @splat(0));
        hasher.update(pad[0..pad_len]);
    }
    return hasher.final();
}

/// XCTR from HCTR2: XORs `src` with the encryptions of z ^ 1, z ^ 2 and so on, and writes the result to `dst`, which can be `src`.
pub fn xctr(comptime Aes: type, ks_enc: *const aes.AesEncryptCtx(Aes), dst: []u8, src: []const u8, z: [16]u8) void {
    const block_length = 16;
    const batch = Aes.block.parallel.optimal_parallel_blocks;
    const batch_length = block_length * batch;
    const z_lo = mem.readInt(u64, z[0..8], .little);
    var counters: [batch_length]u8 = undefined;
    for (0..batch) |j| counters[j * block_length + 8 ..][0..8].* = z[8..].*;
    var counter: u64 = 1;
    var i: usize = 0;

    while (i + batch_length <= src.len) : (i += batch_length) {
        inline for (0..batch) |j| {
            mem.writeInt(u64, counters[j * block_length ..][0..8], z_lo ^ (counter + j), .little);
        }
        counter += batch;
        ks_enc.xorWide(batch, dst[i..][0..batch_length], src[i..][0..batch_length], counters);
    }

    const counter_bytes = counters[0..block_length];
    while (i < src.len) : (i += block_length) {
        mem.writeInt(u64, counter_bytes[0..8], z_lo ^ counter, .little);
        counter += 1;
        var keystream: [block_length]u8 = undefined;
        ks_enc.encrypt(&keystream, counter_bytes);
        const left = @min(block_length, src.len - i);
        for (dst[i..][0..left], src[i..][0..left], keystream[0..left]) |*d, x, k| {
            d.* = x ^ k;
        }
    }
}

fn expectVector(comptime Cipher: type, comptime key_hex: []const u8, comptime tweak_hex: []const u8, comptime plaintext_hex: []const u8, comptime ciphertext_hex: []const u8) !void {
    var key: [key_hex.len / 2]u8 = undefined;
    var tweak: [tweak_hex.len / 2]u8 = undefined;
    var plaintext: [plaintext_hex.len / 2]u8 = undefined;
    var expected: [ciphertext_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, key_hex);
    _ = try std.fmt.hexToBytes(&tweak, tweak_hex);
    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);
    _ = try std.fmt.hexToBytes(&expected, ciphertext_hex);

    var cipher = Cipher.init(key);
    var buf = plaintext;
    try cipher.encrypt(&buf, &buf, &tweak);
    try std.testing.expectEqualSlices(u8, &expected, &buf);
    try cipher.decrypt(&buf, &buf, &tweak);
    try std.testing.expectEqualSlices(u8, &plaintext, &buf);
}

test "official test vectors" {
    // From https://github.com/google/hctr2, test_vectors/ours/HCTR2.
    try expectVector(Hctr2_128, "74f98f60786abfa85b0bbba059e0f91e", "", "6b26837bdc1c583dc142c6ab7b3f43b0", "dd05a8ae51f1e8212fd6c33b9467036d");
    try expectVector(Hctr2_128, "8171c4d67e21d6a250235be986da8e3f", "10", "5477797774f15a78b691d443b14be3560b88f5b95977549508e85ebd7f31bb", "0a999af4e64b89473ae7ce0c1e06a03275e74f5640af8f15af291e04a097cd");
    try expectVector(Hctr2_128, "3e085d646c98ecec700e0da141209982", "11b777910d99d98d353af7146b0937e5ad51f6c3964b6456a8bd81ccbe94afe4", "ff8db9c0e369b3b28b1126b311ecfbb99cc171d6e3260ee0684060b93a63568a9ec1f010b1643270f8cdc6c4494ce1cef3e103f835aee05eef5fbc41752613cc3785dfc05da64798f197525804e6b501c0b8176d74bd9adfa4379486b0138328c9a2073fb5b272400e60df5707b72c66103f8ddd300a47d5e89dfba1af53d705c7d2bae72ca0bfb8d193e74182a3413aaf12d6f834da9246ada22ff67e4696d803f34964ded8068ba0bc633538b66bda5b503f13a5841b1b668995b7c2163ce924b08c6f49eff7286a24fdbe25e2b490774408b8dad2de2ca057455729476b894af6a72ac39e7bc8fd9f89abee6da3b423907ae989a0c7b317418791fc9742", "fc9b9666c4822a4ab124bac7785f79c1572e47294d7bd29abdc6c1267b8e3f5dd4b49f6a02244aad0c001bdf92c58ae17779ccd520bf83f44bad11bfdb47657043f365dfb7dcb2b9aa3fb3df79690da0861cba480b01c188df03b1063c1d56a18e98c1a695a25b727659d22625cdef7cc960ea43d1128a8a631278cb2f881e887859deba4d2c7861753754fd80c75e98cf14628efb72ee4d9faf8b09e5210a918f8887d5b184ab180857ed7235a60ec6ffcbfe2c48391444ba59323a2dc45fcbbe688e7bee21a43211a099fd90de5943ebedd5876846c6de0b0717596aabca15650201b6718c3baa183b30ae385b2c74d4ee4afcf71b09d4da8b1d5d6f216c");
    try expectVector(Hctr2_256, "5be4575e4b0376545b4c2f703439df278a32a9f7312e84e948219b68cf7eecfc", "57729031780138bb0590c330c4928fb9", "00a3282b76c27afbf0dc8a318c15ad2a0f", "64400ceed0075e9c39483bcb3a5d701741");
    try expectVector(Hctr2_256, "f1aa1e275e260877bf505c38a471e895c9d79aad0078d0aa800c36a6bb0c33ab", "21182a24be4b057e797affc92df626c132fa4b3eb6129d5bd06904bf82e52676cc9c72bd723bdd9586b3dcf32e73c6", "0cbd27848158029ff1df0a4ddb1d16a479106484a6b4ce73af8e264127c89df64040e4d6fe87fed4cfbaca42d5f111c78cd26f4da9d57189aec5be204d3075da466e59548d22c1f1d511f339166180c94d63806cc8f2cf41bcc0bd61ac4851e1f6a1a89518ea9907d9919ac216a76ecc7fa880cf30d93e1713fc3c832ac311edb3f487c5f29bdba613fe8383355297f055bfe1799e36833f2d8a3404a0265fba3f0fbf15c957c5ccd2e226290b156d5ac79e0c200a227639f9e9b33aa6f2e175b5da5561653316558ebb58d4c8cbb9bf32f5caef68e2e0153279a6bb3863fa8cf52711eb88f529371231734dc64b100a995ba7e19f28552d87a7400a705cf0f36c6583947c43ad8f98c2534795b827490b3c59a76c04df9d86f9792927c60e6dd6c457aa1866d9194792220feedb4265a5764ccdeefd031ba58e12d5efdce04472787720a1994be233174da33e6b73389e3eaf27679df642723f65d2cf9becb9e9a9e5732220e4ec11248338fcd421e70aca3dbdc8de857273e6dd70a05319ec30b14f7c00a8d948917aa68a05eacd335e359940b9bcf1a5b8fe647ec43a3bf1347afc73248940e0c44dcf8c57d943cd097c0cc0844e684f7c09b6668d263332924a1ffb498ee64adf2dc0cde639c4a418e4fe5425910775e9e0ffcb06dc738b19a40a9c056bae9cc07b9e2ae1c232842e6604d40f3a367e6004d0ef71cf488e", "1df313e21c9b8670ed7dee86a1c53052650d2d40139df8fdedc5125fae30b47e6b9e7f2e335455776b8530b1fb14562c9ea33cc45f12e966964f8a48b8528ad551e0477fe1ccad6cff459a05ddd8bacc3f81a293f5fe05ea79fbc0f1718624ee705981e78c7e6f4b0d170ce365de6250001d6d4171ad935b54a61d49d152bae8cca2622061fc7fbfee868429529a48512ae10eab7ae551558da38e8d00d04117ac4bcba3524a403715e33eb1190b16ba7d1af5184012a9219e9edaab9262715db46423c8c18e29ce1be1cb55a601ab3cec5e6fd3fc670826275a56a7ea697d7c77bd49ae3e04345d121c00665f79b10d14cacc14bb3d8fa70a5f92a9715bd7a3fafeee5004da0c82f29133479a79f4bcb9ba9b6aa795877f08b96266e6a145d0037badc51a694828babf819ddd4512cd0b500bb5ccda366d10f8a20ca6c942d850fd5a957daad5b93525444cdba660ea19954c2445330521525fbc2b3446d2ac10c0c3d667d5fd43bfcecc661481966e7d3fa9b29ecf9a23918b51b3aa3cf1238ced903cd3a7d6c64cea4550440ead94a5ad133124a03e7605a6126471ea506a7cc7f19823ba2ff19eb3b26d8d76afa63ce64ce8deb7531afa6fb6ed598f1b6fe35f864db52add35cf6cdeb312e278475387b9b18eebe3a352a2ce8106e219947e8c4387dba18021a4a2643e51f26f48c8f9182aaaeb2db7139bbc2ab23ea93e");
}
