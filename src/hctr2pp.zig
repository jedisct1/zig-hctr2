const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;

/// HCTR2++ using an AES-128 master key.
pub const Hctr2pp_128 = Hctr2pp(aes.Aes128);

/// HCTR2++ using an AES-256 master key.
///
/// AES-256 derives the hash and re-keying subkeys only.
/// R3 uses 128-bit ephemeral keys, so its block-cipher calls always use
/// AES-128.
/// Both variants therefore provide 128-bit effective security.
/// Use this variant only when a 256-bit master key is required.
pub const Hctr2pp_256 = Hctr2pp(aes.Aes256);

/// Bytes in each 2n-bit hash block, where n is 128.
pub const hash_block_length = 32;

const Elem = [4]u64;

/// Carryless multiplication of two 64-bit values.
///
/// This uses the masked multiplication method from BearSSL's `ghash_ctmul64`,
/// so its running time does not depend on the operands.
/// Handling the low four bits separately prevents ordinary multiplication
/// carries from corrupting the carryless product.
fn bmul64(x: u64, y: u64) u128 {
    const m0: u128 = 0x11111111111111111111111111111111;
    const m1 = m0 << 1;
    const m2 = m0 << 2;
    const m3 = m0 << 3;

    const xh = @as(u128, x & ~@as(u64, 0xf));
    const x0 = xh & m0;
    const x1 = xh & m1;
    const x2 = xh & m2;
    const x3 = xh & m3;
    const y0 = @as(u128, y) & m0;
    const y1 = @as(u128, y) & m1;
    const y2 = @as(u128, y) & m2;
    const y3 = @as(u128, y) & m3;

    const z0 = (x0 *% y0) ^ (x1 *% y3) ^ (x2 *% y2) ^ (x3 *% y1);
    const z1 = (x0 *% y1) ^ (x1 *% y0) ^ (x2 *% y3) ^ (x3 *% y2);
    const z2 = (x0 *% y2) ^ (x1 *% y1) ^ (x2 *% y0) ^ (x3 *% y3);
    const z3 = (x0 *% y3) ^ (x1 *% y2) ^ (x2 *% y1) ^ (x3 *% y0);

    var low: u128 = 0;
    inline for (0..4) |k| {
        const mask = @as(u64, 0) -% ((x >> k) & 1);
        low ^= @as(u128, mask & y) << k;
    }

    return ((z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3)) ^ low;
}

/// Multiplies in GF(2^256) using x^256 + x^10 + x^5 + x^2 + 1.
///
/// Elements are little-endian: bit i of limb j represents x^(64j + i).
fn gfMul(a: Elem, b: Elem) Elem {
    var t: [8]u64 = @splat(0);
    for (0..4) |i| {
        for (0..4) |j| {
            const p = bmul64(a[i], b[j]);
            t[i + j] ^= @as(u64, @truncate(p));
            t[i + j + 1] ^= @as(u64, @truncate(p >> 64));
        }
    }

    // Reduce the upper half with the field polynomial.
    const hi = t[4..8].*;
    var res: Elem = t[0..4].*;
    var overflow: u64 = 0;
    for (&res, hi) |*limb, h| {
        limb.* ^= h;
    }
    inline for (.{ 2, 5, 10 }) |s| {
        var prev: u64 = 0;
        for (&res, hi) |*limb, h| {
            limb.* ^= (h << s) | (prev >> (64 - s));
            prev = h;
        }
        overflow ^= hi[3] >> (64 - s);
    }
    // The remaining terms fit entirely in the first limb.
    res[0] ^= overflow ^ (overflow << 2) ^ (overflow << 5) ^ (overflow << 10);
    return res;
}

fn elemFromBytes(bytes: *const [hash_block_length]u8) Elem {
    var e: Elem = undefined;
    for (&e, 0..) |*limb, i| {
        limb.* = mem.readInt(u64, bytes[i * 8 ..][0..8], .little);
    }
    return e;
}

fn elemToBytes(e: Elem) [hash_block_length]u8 {
    var bytes: [hash_block_length]u8 = undefined;
    for (e, 0..) |limb, i| {
        mem.writeInt(u64, bytes[i * 8 ..][0..8], limb, .little);
    }
    return bytes;
}

fn elemXor(a: Elem, b: Elem) Elem {
    return .{ a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3] };
}

fn hashUpdate(acc: *Elem, key: Elem, block: *const [hash_block_length]u8) void {
    acc.* = gfMul(elemXor(acc.*, elemFromBytes(block)), key);
}

/// A 2n-bit POLYVAL-style universal hash over GF(2^256).
///
/// The HCTR2 encoding hashes a length block, the zero-padded tweak, and the
/// message padded with one bit followed by zeros.
fn hash2n(key: Elem, tweak: []const u8, msg: []const u8) [hash_block_length]u8 {
    const tweak_len_bits = @as(u128, tweak.len) * 8;
    const len_code: u128 = if (msg.len % hash_block_length == 0)
        2 * tweak_len_bits + 2
    else
        2 * tweak_len_bits + 3;
    var len_block: [hash_block_length]u8 = @splat(0);
    mem.writeInt(u128, len_block[0..16], len_code, .little);

    var acc: Elem = @splat(0);
    hashUpdate(&acc, key, &len_block);

    var i: usize = 0;
    while (i + hash_block_length <= tweak.len) : (i += hash_block_length) {
        hashUpdate(&acc, key, tweak[i..][0..hash_block_length]);
    }
    if (i < tweak.len) {
        var block: [hash_block_length]u8 = @splat(0);
        @memcpy(block[0 .. tweak.len - i], tweak[i..]);
        hashUpdate(&acc, key, &block);
    }

    i = 0;
    while (i + hash_block_length <= msg.len) : (i += hash_block_length) {
        hashUpdate(&acc, key, msg[i..][0..hash_block_length]);
    }
    if (i < msg.len) {
        var block: [hash_block_length]u8 = @splat(0);
        @memcpy(block[0 .. msg.len - i], msg[i..]);
        block[msg.len - i] = 1;
        hashUpdate(&acc, key, &block);
    }

    return elemToBytes(acc);
}

/// HCTR2++ (HCTR++) is a beyond-birthday-bound variant of HCTR2.
///
/// It combines HCTR2's hash-encrypt-hash structure with R3 fresh re-keying
/// and a 2n-bit universal hash.
/// With unique tweaks, it provides strong pseudorandom permutation security
/// up to roughly 2^n operations.
/// Reusing a tweak reduces that bound.
///
/// The construction derives two hash keys and an R3 re-keying key from the
/// master key.
/// It hashes the tweak and message around the first block, while CTR++ creates
/// each bulk keystream block under a fresh R3-derived key.
///
/// Hash blocks are 32-byte little-endian polynomials in GF(2^256), defined by
/// x^256 + x^10 + x^5 + x^2 + 1.
///
/// Ciphertexts have the same length as plaintexts, but HCTR2++ does not
/// authenticate them.
/// Use an AEAD mode when integrity is required.
/// Messages must be at least one AES block (16 bytes).
///
/// R3 re-keying costs an AES key schedule, an AES call, and two field
/// multiplications per message block, so this mode is slower than HCTR2.
///
/// `Aes` selects AES-128 or AES-256 for subkey derivation.
pub fn Hctr2pp(comptime Aes: anytype) type {
    const aes_block_length = Aes.block.block_length;

    return struct {
        const State = @This();

        h1: Elem,
        h2: Elem,
        h12: Elem,
        kk: Elem,
        r3_init: Elem,

        /// HCTR2++ does not produce authentication tags.
        pub const tag_length = 0;

        /// HCTR2++ uses tweaks rather than fixed-size nonces.
        pub const nonce_length = 0;

        /// Bytes in the master key: 16 for AES-128 or 32 for AES-256.
        pub const key_length = Aes.key_bits / 8;

        /// Bytes in an AES block.
        pub const block_length = aes_block_length;

        /// Creates cipher state from a master key.
        ///
        /// The master cipher derives the hash and re-keying subkeys only.
        /// R3 uses AES-128 ephemeral keys, so both variants have 128-bit
        /// effective security.
        pub fn init(key: [key_length]u8) State {
            const ks = Aes.initEnc(key);
            var blocks: [6 * aes_block_length]u8 = @splat(0);
            inline for (0..6) |i| {
                blocks[i * aes_block_length] = i + 1;
            }
            ks.encryptWide(6, &blocks, &blocks);

            const h1 = elemFromBytes(blocks[0..hash_block_length]);
            const h2 = elemFromBytes(blocks[hash_block_length .. 2 * hash_block_length]);
            const kk = elemFromBytes(blocks[2 * hash_block_length ..]);

            return State{
                .h1 = h1,
                .h2 = h2,
                .h12 = elemXor(h1, h2),
                .kk = kk,
                // Precompute the fixed length block used by each R3 hash.
                .r3_init = gfMul(.{ 3, 0, 0, 0 }, kk),
            };
        }

        const Direction = enum { encrypt, decrypt };

        /// Encrypts plaintext with HCTR2++.
        ///
        /// `ciphertext` must be the same length as `plaintext`, which must be
        /// at least 16 bytes.
        /// The tweak separates encryption domains and should be unique for the
        /// strongest security bound.
        ///
        /// Returns `error.InputTooShort` for plaintexts shorter than 16 bytes.
        pub fn encrypt(state: *State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            try state.hctr2pp(ciphertext, plaintext, tweak, .encrypt);
        }

        /// Decrypts ciphertext with HCTR2++.
        ///
        /// `plaintext` must be the same length as `ciphertext`, which must be
        /// at least 16 bytes.
        ///
        /// Returns `error.InputTooShort` for ciphertexts shorter than 16 bytes.
        pub fn decrypt(state: *State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            try state.hctr2pp(plaintext, ciphertext, tweak, .decrypt);
        }

        /// Derives an ephemeral AES key and mask from an R3 nonce.
        ///
        /// The paper does not define H_K(r) precisely.
        /// This implementation hashes `r` as a message with an empty tweak,
        /// reusing the mode's hash and a precomputed length block.
        fn r3(state: *const State, r: *const [aes_block_length]u8) struct { u: [aes_block_length]u8, v: [aes_block_length]u8 } {
            var block: [hash_block_length]u8 = @splat(0);
            block[0..aes_block_length].* = r.*;
            block[aes_block_length] = 1;
            const digest = elemToBytes(gfMul(elemXor(state.r3_init, elemFromBytes(&block)), state.kk));
            return .{
                .u = digest[0..aes_block_length].*,
                .v = digest[aes_block_length..].*,
            };
        }

        fn hctr2pp(state: *State, dst: []u8, src: []const u8, tweak: []const u8, comptime direction: Direction) !void {
            assert(dst.len == src.len);
            if (src.len < aes_block_length) {
                return error.InputTooShort;
            }

            // Swapping the hash keys for decryption makes this path self-inverse.
            const hk_in = if (direction == .encrypt) state.h1 else state.h2;
            const hk_out = if (direction == .encrypt) state.h2 else state.h1;

            const first = src[0..aes_block_length].*;
            const bulk = src[aes_block_length..];

            const x1 = hash2n(hk_in, tweak, bulk);
            var pp1: [aes_block_length]u8 = undefined;
            for (&pp1, first, x1[0..aes_block_length].*) |*p, a, b| {
                p.* = a ^ b;
            }
            const re = x1[aes_block_length..].*;

            const ke = state.r3(&re);
            var cc: [aes_block_length]u8 = undefined;
            for (&cc, pp1, ke.v) |*p, a, b| {
                p.* = a ^ b;
            }
            aes.Aes128.initEnc(ke.u).encrypt(&cc, &cc);
            for (&cc, ke.v) |*p, x| {
                p.* ^= x;
            }

            const rj = hash2n(state.h12, tweak, &cc);
            const r = rj[0..aes_block_length].*;
            const j = rj[aes_block_length..].*;

            const dst_first = dst[0..aes_block_length];
            const dst_bulk = dst[aes_block_length..];
            state.ctrPp(dst_bulk, bulk, r, j);

            const x2 = hash2n(hk_out, tweak, dst_bulk);
            const rd = x2[aes_block_length..].*;

            const kd = state.r3(&rd);
            var pp2: [aes_block_length]u8 = undefined;
            for (&pp2, cc, kd.v) |*p, a, b| {
                p.* = a ^ b;
            }
            aes.Aes128.initDec(kd.u).decrypt(&pp2, &pp2);
            for (dst_first, pp2, kd.v, x2[0..aes_block_length].*) |*p, a, b, c| {
                p.* = a ^ b ^ c;
            }
        }

        /// Generates counter-mode keystream with a fresh R3-derived key per block.
        fn ctrPp(state: *const State, dst: []u8, src: []const u8, r: [aes_block_length]u8, j: [aes_block_length]u8) void {
            var counter: u128 = 1;
            var i: usize = 0;
            while (i < src.len) : ({
                i += aes_block_length;
                counter += 1;
            }) {
                var counter_bytes: [aes_block_length]u8 = undefined;
                mem.writeInt(u128, &counter_bytes, counter, .little);

                var ri: [aes_block_length]u8 = undefined;
                var ji: [aes_block_length]u8 = undefined;
                for (&ri, &ji, r, j, counter_bytes) |*p, *q, a, b, c| {
                    p.* = a ^ c;
                    q.* = b ^ c;
                }

                const ki = state.r3(&ri);
                var si: [aes_block_length]u8 = undefined;
                for (&si, ji, ki.v) |*p, a, b| {
                    p.* = a ^ b;
                }
                aes.Aes128.initEnc(ki.u).encrypt(&si, &si);
                for (&si, ki.v) |*p, x| {
                    p.* ^= x;
                }

                const left = @min(aes_block_length, src.len - i);
                for (dst[i..][0..left], src[i..][0..left], si[0..left]) |*d, s, c| {
                    d.* = s ^ c;
                }
            }
        }
    };
}

fn xorshift(state: *u64) u64 {
    state.* ^= state.* << 13;
    state.* ^= state.* >> 7;
    state.* ^= state.* << 17;
    return state.*;
}

fn randomElem(state: *u64) Elem {
    return .{ xorshift(state), xorshift(state), xorshift(state), xorshift(state) };
}

/// Reference GF(2^256) multiplication used to check `gfMul`.
fn slowMul(a: Elem, b: Elem) Elem {
    var res: Elem = @splat(0);
    var cur = a;
    for (b) |limb| {
        for (0..64) |bit| {
            if ((limb >> @intCast(bit)) & 1 == 1) {
                res = elemXor(res, cur);
            }
            // Multiply by x and reduce with the field polynomial.
            const carry = cur[3] >> 63;
            cur[3] = (cur[3] << 1) | (cur[2] >> 63);
            cur[2] = (cur[2] << 1) | (cur[1] >> 63);
            cur[1] = (cur[1] << 1) | (cur[0] >> 63);
            cur[0] = (cur[0] << 1) ^ (carry * 0x425);
        }
    }
    return res;
}

test "HCTR2++ gfMul matches bit-by-bit reference" {
    var state: u64 = 0x123456789abcdef0;
    for (0..50) |_| {
        const a = randomElem(&state);
        const b = randomElem(&state);
        try std.testing.expectEqual(slowMul(a, b), gfMul(a, b));
    }
}

test "HCTR2++ gfMul matches reference on dense operands" {
    // Full residue classes ensure masked multiplication never leaks ordinary carries.
    const ones: Elem = @splat(~@as(u64, 0));
    try std.testing.expectEqual(slowMul(ones, ones), gfMul(ones, ones));

    const classes = [_]u64{ 0x1111111111111111, 0x2222222222222222, 0x4444444444444444, 0x8888888888888888 };
    var state: u64 = 0x0fedcba987654321;
    for (classes) |cx| {
        for (classes) |cy| {
            var a = randomElem(&state);
            var b = randomElem(&state);
            a[1] |= cx;
            b[2] |= cy;
            try std.testing.expectEqual(slowMul(a, b), gfMul(a, b));
        }
    }
}

test "HCTR2++ gfMul identity and commutativity" {
    const one: Elem = .{ 1, 0, 0, 0 };
    var state: u64 = 0xdeadbeefcafef00d;
    for (0..20) |_| {
        const a = randomElem(&state);
        const b = randomElem(&state);
        try std.testing.expectEqual(a, gfMul(a, one));
        try std.testing.expectEqual(gfMul(b, a), gfMul(a, b));
    }
}

test "HCTR2++ hash2n separates inputs" {
    const key: Elem = .{ 2, 0, 0, 0 };
    const zeros: [64]u8 = @splat(0);
    try std.testing.expect(!mem.eql(u8, &hash2n(key, "", "a"), &hash2n(key, "a", "")));
    try std.testing.expect(!mem.eql(u8, &hash2n(key, "t", "m"), &hash2n(key, "t", "m\x00")));
    try std.testing.expect(!mem.eql(u8, &hash2n(key, "", zeros[0..32]), &hash2n(key, "", zeros[0..64])));
}

test "HCTR2++-128 encrypt/decrypt round-trip" {
    const key: [16]u8 = @splat(0);
    var state = Hctr2pp_128.init(key);

    const plaintext = "Hello, HCTR2++ World!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const tweak = "test tweak";

    try state.encrypt(&ciphertext, plaintext, tweak);
    try std.testing.expect(!mem.eql(u8, plaintext, &ciphertext));

    try state.decrypt(&decrypted, &ciphertext, tweak);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "HCTR2++-128 round-trip for all lengths" {
    var key: [16]u8 = undefined;
    for (&key, 0..) |*b, i| {
        b.* = @truncate(i * 7 + 1);
    }
    var state = Hctr2pp_128.init(key);
    const tweak = "length sweep";

    var plaintext: [100]u8 = undefined;
    for (&plaintext, 0..) |*b, i| {
        b.* = @truncate(i * 13 + 5);
    }

    var len: usize = 16;
    while (len <= plaintext.len) : (len += 1) {
        var ciphertext: [plaintext.len]u8 = undefined;
        var decrypted: [plaintext.len]u8 = undefined;
        try state.encrypt(ciphertext[0..len], plaintext[0..len], tweak);
        try state.decrypt(decrypted[0..len], ciphertext[0..len], tweak);
        try std.testing.expectEqualSlices(u8, plaintext[0..len], decrypted[0..len]);
    }
}

test "HCTR2++-128 minimum block size" {
    const key: [16]u8 = @splat(0);
    var state = Hctr2pp_128.init(key);

    const plaintext: [16]u8 = @splat(0x42);
    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    try state.encrypt(&ciphertext, &plaintext, "");
    try state.decrypt(&decrypted, &ciphertext, "");

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR2++-128 input too short" {
    const key: [16]u8 = @splat(0);
    var state = Hctr2pp_128.init(key);

    const plaintext: [15]u8 = @splat(0x42);
    var ciphertext: [15]u8 = undefined;

    try std.testing.expectError(error.InputTooShort, state.encrypt(&ciphertext, &plaintext, ""));
}

test "HCTR2++-128 different tweaks produce different ciphertexts" {
    const key: [16]u8 = @splat(0);
    var state = Hctr2pp_128.init(key);

    const plaintext: [32]u8 = @splat(0x42);
    var ciphertext1: [32]u8 = undefined;
    var ciphertext2: [32]u8 = undefined;

    try state.encrypt(&ciphertext1, &plaintext, "tweak1");
    try state.encrypt(&ciphertext2, &plaintext, "tweak2");

    try std.testing.expect(!mem.eql(u8, &ciphertext1, &ciphertext2));
}

test "HCTR2++-128 deterministic" {
    var key: [16]u8 = undefined;
    for (&key, 0..) |*b, i| {
        b.* = @truncate(i);
    }
    var state1 = Hctr2pp_128.init(key);
    var state2 = Hctr2pp_128.init(key);

    const plaintext: [64]u8 = @splat(0x55);
    var ciphertext1: [64]u8 = undefined;
    var ciphertext2: [64]u8 = undefined;

    try state1.encrypt(&ciphertext1, &plaintext, "t");
    try state2.encrypt(&ciphertext2, &plaintext, "t");

    try std.testing.expectEqualSlices(u8, &ciphertext1, &ciphertext2);
}

test "HCTR2++-128 avalanche" {
    const key: [16]u8 = @splat(7);
    var state = Hctr2pp_128.init(key);

    const plaintext: [64]u8 = @splat(0);
    var modified = plaintext;
    modified[63] ^= 1;

    var ciphertext1: [64]u8 = undefined;
    var ciphertext2: [64]u8 = undefined;
    try state.encrypt(&ciphertext1, &plaintext, "t");
    try state.encrypt(&ciphertext2, &modified, "t");

    // Flipping the last plaintext bit must change the first ciphertext block.
    try std.testing.expect(!mem.eql(u8, ciphertext1[0..16], ciphertext2[0..16]));
    // ... and the keystream over the bulk as well.
    try std.testing.expect(!mem.eql(u8, ciphertext1[16..48], ciphertext2[16..48]));
}

test "HCTR2++-128 large message" {
    const key: [16]u8 = @splat(0);
    var state = Hctr2pp_128.init(key);

    const plaintext: [1024]u8 = @splat(0xAB);
    var ciphertext: [1024]u8 = undefined;
    var decrypted: [1024]u8 = undefined;

    try state.encrypt(&ciphertext, &plaintext, "large tweak");
    try state.decrypt(&decrypted, &ciphertext, "large tweak");

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR2++-128 long tweak" {
    const key: [16]u8 = @splat(3);
    var state = Hctr2pp_128.init(key);

    const plaintext: [40]u8 = @splat(0x11);
    const tweak: [100]u8 = @splat(0x77);
    var ciphertext: [40]u8 = undefined;
    var decrypted: [40]u8 = undefined;

    try state.encrypt(&ciphertext, &plaintext, &tweak);
    try state.decrypt(&decrypted, &ciphertext, &tweak);

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR2++-256 encrypt/decrypt round-trip" {
    const key: [32]u8 = @splat(0);
    var state = Hctr2pp_256.init(key);

    const plaintext = "Hello, HCTR2++-256 World!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const tweak = "test tweak 256";

    try state.encrypt(&ciphertext, plaintext, tweak);
    try state.decrypt(&decrypted, &ciphertext, tweak);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

fn testKey128() [16]u8 {
    var key: [16]u8 = undefined;
    for (&key, 0..) |*b, i| {
        b.* = @truncate(i);
    }
    return key;
}

fn hexElem(comptime hex: []const u8) Elem {
    var bytes: [hash_block_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return elemFromBytes(&bytes);
}

// Known-answer vectors generated with an independent Python implementation of
// the Figure 4 pseudocode: big-int GF(2^256) arithmetic and AES from the
// cryptography library, no shared code. They match the Rust implementation in
// rust-hctr2.

test "HCTR2++ KAT subkeys" {
    const state = Hctr2pp_128.init(testKey128());

    try std.testing.expectEqual(
        hexElem("e37cd363dd7c87a09aff0e3e60e09c82fb8ae31ba5db9cad97364d8722d47326"),
        state.h1,
    );
    try std.testing.expectEqual(
        hexElem("8cb899148f1fa8ff9132d0eb15a936f2f08c8d049312eac76f8fa05078178aa1"),
        state.h2,
    );
    try std.testing.expectEqual(
        hexElem("789dc76ccb52ce1c3db90ecb357af60eeb3ee851461107fec27297b27ad5e563"),
        state.kk,
    );
}

test "HCTR2++ KAT hash2n" {
    const state = Hctr2pp_128.init(testKey128());

    var msg40: [40]u8 = undefined;
    for (&msg40, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    const cases = [_]struct { tweak: []const u8, msg: []const u8, expected: []const u8 }{
        .{ .tweak = "", .msg = "", .expected = "c6f9a6c7baf90e4135ff1d7cc0c03905f715c7374ab7395b2f6d9a0e45a8e74c" },
        .{ .tweak = "tweak", .msg = "", .expected = "3c4414e8acf1f1bc7f9674c74043855751ef29e9513bdcf7fec97f76776ec5d6" },
        .{ .tweak = "", .msg = msg40[0..16], .expected = "6bcd860a4f8467fee40f2ae865cf74f010994a07f5c9b0248be2ffff87f29fad" },
        .{ .tweak = "tweak", .msg = &msg40, .expected = "89e96782de662ce1592258b6abc040597d3abaea2e6c86ffee481ff7afb9b858" },
    };
    for (cases) |case| {
        var expected: [hash_block_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, case.expected);
        try std.testing.expectEqual(expected, hash2n(state.h1, case.tweak, case.msg));
    }
}

test "HCTR2++ KAT R3 re-keying" {
    const state = Hctr2pp_128.init(testKey128());

    const r = testKey128();
    const kv = state.r3(&r);

    var expected_u: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_u, "cf53026c002409032271b44d2cfb76ae");
    var expected_v: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_v, "cc0108efd8d927ec03a148f06bec9c38");

    try std.testing.expectEqual(expected_u, kv.u);
    try std.testing.expectEqual(expected_v, kv.v);
}

test "HCTR2++-128 KAT encrypt" {
    var state = Hctr2pp_128.init(testKey128());

    const cases = [_]struct { tweak: []const u8, pt: []const u8, ct: []const u8 }{
        .{
            .tweak = "",
            .pt = "000102030405060708090a0b0c0d0e0f",
            .ct = "02c3c1ea3033a092e21a16acaf88121b",
        },
        .{
            .tweak = "tweak",
            .pt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            .ct = "46feab9309b3e5826370ad00561963c698a293833efa5ce25c23786df2f4abad",
        },
        .{
            .tweak = "",
            .pt = "050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa" ++
                "01080f161d242b323940474e55",
            .ct = "8ce2a701bc7547a38212d07087d365b4bf6b4bfe530436ec11f9087b813457a013fcfc18" ++
                "9b0ca9e172c2a3c148ab621beb",
        },
    };

    const tweak3 = "0104070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e6164676a" ++
        "6d707376797c7f8285888b8e9194979a9da0a3a6a9acafb2b5b8bbbec1c4c7cacdd0";

    inline for (cases, 0..) |case, n| {
        var pt: [case.pt.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pt, case.pt);
        var expected_ct: [case.ct.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_ct, case.ct);

        var tweak_buf: [tweak3.len / 2]u8 = undefined;
        const tweak: []const u8 = if (n == 2) try std.fmt.hexToBytes(&tweak_buf, tweak3) else case.tweak;

        var ct: [pt.len]u8 = undefined;
        try state.encrypt(&ct, &pt, tweak);
        try std.testing.expectEqualSlices(u8, &expected_ct, &ct);

        var decrypted: [pt.len]u8 = undefined;
        try state.decrypt(&decrypted, &ct, tweak);
        try std.testing.expectEqualSlices(u8, &pt, &decrypted);
    }
}

test "HCTR2++-256 KAT encrypt" {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| {
        b.* = @truncate(i);
    }
    var state = Hctr2pp_256.init(key);

    var pt: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pt, "03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3");
    var expected_ct: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_ct, "d885008594f696577cd7bf4478d27965d8741fd5eda96612e8ef397df08a4d0fec");

    var ct: [33]u8 = undefined;
    try state.encrypt(&ct, &pt, "tweak 256");
    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);

    var decrypted: [33]u8 = undefined;
    try state.decrypt(&decrypted, &ct, "tweak 256");
    try std.testing.expectEqualSlices(u8, &pt, &decrypted);
}
