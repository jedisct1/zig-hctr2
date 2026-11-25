const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const DualPolyval = @import("polyval.zig").Polyval(2);
const KMac256 = crypto.hash.sha3.KMac256;
const Aes128 = aes.Aes128;
const Aes256 = aes.Aes256;
const Aes128EncryptCtx = aes.AesEncryptCtx(Aes128);
const Aes128DecryptCtx = aes.AesDecryptCtx(Aes128);
const Aes256EncryptCtx = aes.AesEncryptCtx(Aes256);

const block_length = 16;
const head_length = 2 * block_length;
const Block = [block_length]u8;
const Vec = @Vector(block_length, u8);

/// The frame width the paper recommends.
/// Each frame of `w` blocks costs one extra AES call, and security goes up to about 2^128 / w blocks.
pub const default_frame_width = 4096;

/// How the 32-byte master key is turned into the hash keys and the AES keys.
pub const KeyDerivation = enum {
    /// One AES call at key setup, enough for confidentiality but with no key commitment.
    one_call,
    /// Seven AES calls at key setup.
    /// With `EtesHcenc`, it also commits to the key, but only up to about 60 bits.
    two_stage,
};

pub const Options = struct {
    frame_width: u64 = default_frame_width,
    key_derivation: KeyDerivation = .one_call,
};

/// HCENC with the one-call key derivation and the recommended frame width.
pub const Hcenc_128 = Hcenc(.{});

/// HCENC, a wide-block tweakable cipher built on AES-128, with security well beyond the birthday bound.
/// From "HCENC: How to Design an Efficient Committing Beyond-Birthday-Bound Accordion from a Block Cipher with n-Bit Blocks and Keys".
///
/// Inputs must be at least 32 bytes long, and tweaks can have any length.
/// The ciphertext is as long as the plaintext, and nothing is authenticated.
/// Use `EtesHcenc` or `UcxHcenc` if you need authenticated encryption.
pub fn Hcenc(comptime options: Options) type {
    comptime assert(options.frame_width >= 1 and options.frame_width < std.math.maxInt(u64));

    return struct {
        const State = @This();

        hash_keys: DualPolyval,
        k1: Block,
        k2: Block,
        k3: Block,
        ks: Block,

        pub const key_length = 2 * block_length;
        pub const min_message_length = head_length;
        pub const frame_width = options.frame_width;
        pub const key_derivation = options.key_derivation;

        pub fn init(key: [key_length]u8) State {
            const ka = key[0..block_length].*;
            const kb = key[block_length..].*;
            switch (options.key_derivation) {
                .one_call => {
                    var h2: Block = undefined;
                    Aes128.initEnc(ka).encrypt(&h2, &kb);
                    const k1 = mulX(ka);
                    const k2 = mulX(k1);
                    const k3 = mulX(k2);
                    return fromKeys(kb, h2, k1, k2, k3, mulX(k3));
                },
                .two_stage => {
                    var l: Block = undefined;
                    Aes128.initEnc(ka).encrypt(&l, &kb);
                    l = xor(l, kb);
                    var d: [6]Block = undefined;
                    for (&d, 0..) |*dj, j| {
                        var kj = l;
                        kj[0] ^= @intCast(j);
                        Aes128.initEnc(kj).encrypt(dj, &ka);
                    }
                    return fromKeys(d[0], d[1], d[2], d[3], d[4], d[5]);
                },
            }
        }

        fn fromKeys(h1: Block, h2: Block, k1: Block, k2: Block, k3: Block, ks: Block) State {
            return .{
                .hash_keys = DualPolyval.init(.{ h1, h2 }),
                .k1 = k1,
                .k2 = k2,
                .k3 = k3,
                .ks = ks,
            };
        }

        /// Encrypts `plaintext` into `ciphertext`, which can be the same buffer.
        ///
        /// Returns `error.InputTooShort` if the input is shorter than `min_message_length`.
        /// The same tweak and message always give the same ciphertext.
        pub fn encrypt(state: *const State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            assert(ciphertext.len == plaintext.len);
            if (plaintext.len < min_message_length) return error.InputTooShort;
            state.crypt(.encrypt, ciphertext[0..head_length], &.{ciphertext[head_length..]}, plaintext[0..head_length].*, &.{plaintext[head_length..]}, &.{tweak});
        }

        /// Decrypts `ciphertext` into `plaintext`, which can be the same buffer.
        ///
        /// Returns `error.InputTooShort` if the input is shorter than `min_message_length`.
        pub fn decrypt(state: *const State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            assert(ciphertext.len == plaintext.len);
            if (ciphertext.len < min_message_length) return error.InputTooShort;
            state.crypt(.decrypt, plaintext[0..head_length], &.{plaintext[head_length..]}, ciphertext[0..head_length].*, &.{ciphertext[head_length..]}, &.{tweak});
        }

        const Direction = enum { encrypt, decrypt };

        // The tail and the tweak can be split over several buffers, so the AEAD modes can add their extra bytes without copying the message.
        fn crypt(state: *const State, comptime direction: Direction, dst_head: *[head_length]u8, dst_tail: []const []u8, src_head: [head_length]u8, src_tail: []const []const u8, tweak: []const []const u8) void {
            const prefix = state.hashPrefix(tweak, totalLength(src_tail));
            const s_in: u1, const s_out: u1 = if (direction == .encrypt) .{ 0, 1 } else .{ 1, 0 };
            const in = xor(src_head, prefix.finish(s_in, src_tail));
            const out = if (direction == .encrypt) state.head(in) else state.headInverse(in);
            if (prefix.tail_len > 0) {
                const z = xor(in, out);
                var keystream = Keystream(options.frame_width).init(xor(state.ks, z[0..block_length].*), z[block_length..].*);
                keystream.xorParts(dst_tail, src_tail);
            }
            dst_head.* = xor(out, prefix.finish(s_out, dst_tail));
        }

        // Both hashes start with the same length block and tweak, so that part is only hashed once.
        fn hashPrefix(state: *const State, tweak: []const []const u8, tail_len: usize) HashPrefix {
            const tweak_len = totalLength(tweak);
            var hasher = state.hash_keys.hasher();
            var length_block: Block = undefined;
            mem.writeInt(u128, &length_block, 2 * 8 * @as(u128, tweak_len) + 4 + @intFromBool(tail_len % block_length != 0), .little);
            hasher.update(&length_block);
            for (tweak) |part| hasher.update(part);
            return .{ .hasher = hasher, .tweak_len = tweak_len, .tail_len = tail_len };
        }

        fn head(state: *const State, x: [head_length]u8) [head_length]u8 {
            const a = x[0..block_length];
            const b = x[block_length..];
            var g: Block = undefined;
            var u: Block = undefined;
            var v: Block = undefined;
            Aes128.initEnc(xor(state.k1, b.*)).encrypt(&g, a);
            Aes128.initEnc(xor(state.k2, g)).encrypt(&v, b);
            Aes128.initEnc(xor(state.k3, v)).encrypt(&u, &g);
            return u ++ v;
        }

        fn headInverse(state: *const State, y: [head_length]u8) [head_length]u8 {
            const u = y[0..block_length];
            const v = y[block_length..];
            var g: Block = undefined;
            var a: Block = undefined;
            var b: Block = undefined;
            Aes128DecryptCtx.init(xor(state.k3, v.*)).decrypt(&g, u);
            Aes128DecryptCtx.init(xor(state.k2, g)).decrypt(&b, v);
            Aes128DecryptCtx.init(xor(state.k1, b)).decrypt(&a, &g);
            return a ++ b;
        }
    };
}

const HashPrefix = struct {
    hasher: DualPolyval.Hasher,
    tweak_len: usize,
    tail_len: usize,

    /// The paper's H^s for this tail, under both hash keys.
    fn finish(prefix: HashPrefix, comptime s: u1, tail: []const []const u8) [head_length]u8 {
        var hasher = prefix.hasher;
        const tweak_pad = [_]u8{s} ++ @as([block_length - 1]u8, @splat(0));
        hasher.update(tweak_pad[0 .. block_length - prefix.tweak_len % block_length]);
        for (tail) |part| hasher.update(part);
        if (prefix.tail_len % block_length != 0) {
            const tail_pad = [_]u8{1} ++ @as([block_length - 1]u8, @splat(0));
            hasher.update(tail_pad[0 .. block_length - prefix.tail_len % block_length]);
        }
        return hasher.final();
    }
};

/// The CENC keystream of the paper.
///
/// Each frame encrypts w + 1 counters in a row.
/// The first one is the anchor, and each of the others gives a keystream block, XORed with the encrypted anchor.
fn Keystream(comptime w: u64) type {
    const batch = Aes128.block.parallel.optimal_parallel_blocks;

    return struct {
        const Self = @This();

        ctx: Aes128EncryptCtx,
        mask_lo: u64,
        mask_hi: [8]u8,
        counter: u64 = 0,
        anchor: Vec = @splat(0),
        leftover: Block = undefined,
        leftover_len: usize = 0,

        fn init(key: Block, mask: Block) Self {
            return .{
                .ctx = Aes128.initEnc(key),
                .mask_lo = mem.readInt(u64, mask[0..8], .little),
                .mask_hi = mask[8..].*,
            };
        }

        fn isAnchor(counter: u64) bool {
            return counter % (w + 1) == 0;
        }

        fn counterBlocks(ks: *const Self, comptime count: usize) [count * block_length]u8 {
            var out: [count * block_length]u8 = undefined;
            inline for (0..count) |i| {
                mem.writeInt(u64, out[i * block_length ..][0..8], ks.mask_lo ^ (ks.counter + i), .little);
                out[i * block_length + 8 ..][0..8].* = ks.mask_hi;
            }
            return out;
        }

        fn encryptCounter(ks: *Self) Vec {
            var block = ks.counterBlocks(1);
            ks.ctx.encrypt(&block, &block);
            ks.counter += 1;
            return block;
        }

        fn nextBlock(ks: *Self) Block {
            if (isAnchor(ks.counter)) ks.anchor = ks.encryptCounter();
            return ks.encryptCounter() ^ ks.anchor;
        }

        /// The usual case: `batch` blocks of the same frame, done in one pass.
        fn leafBatch(ks: *Self, dst: *[batch * block_length]u8, src: *const [batch * block_length]u8) void {
            var masked: [batch * block_length]u8 = undefined;
            inline for (0..batch) |j| {
                masked[j * block_length ..][0..block_length].* = src[j * block_length ..][0..block_length].* ^ ks.anchor;
            }
            ks.ctx.xorWide(batch, dst, &masked, ks.counterBlocks(batch));
            ks.counter += batch;
        }

        /// Encrypts the next `batch` counters, and returns how many keystream blocks they gave.
        fn blocks(ks: *Self, out: *[batch * block_length]u8) usize {
            out.* = ks.counterBlocks(batch);
            ks.ctx.encryptWide(batch, out, out);
            var n: usize = 0;
            for (0..batch) |i| {
                const o: Vec = out[i * block_length ..][0..block_length].*;
                if (isAnchor(ks.counter + i)) {
                    ks.anchor = o;
                } else {
                    out[n * block_length ..][0..block_length].* = o ^ ks.anchor;
                    n += 1;
                }
            }
            ks.counter += batch;
            return n;
        }

        /// XORs the next `src.len` bytes of keystream into `src`, writing the result to `dst`.
        /// Can be called repeatedly with any lengths, and `dst` can be `src`.
        fn xorBytes(ks: *Self, dst: []u8, src: []const u8) void {
            assert(dst.len == src.len);
            var i: usize = 0;
            if (ks.leftover_len > 0) {
                i = @min(ks.leftover_len, src.len);
                xorInto(dst[0..i], src[0..i], ks.leftover[block_length - ks.leftover_len ..][0..i]);
                ks.leftover_len -= i;
            }

            var buf: [batch * block_length]u8 = undefined;
            while (src.len - i >= batch * block_length) {
                const position = ks.counter % (w + 1);
                if (position != 0 and position + batch <= w + 1) {
                    ks.leafBatch(dst[i..][0 .. batch * block_length], src[i..][0 .. batch * block_length]);
                    i += batch * block_length;
                } else {
                    const n = ks.blocks(&buf) * block_length;
                    xorInto(dst[i..][0..n], src[i..][0..n], buf[0..n]);
                    i += n;
                }
            }

            const rest = src.len - i;
            if (rest == 0) return;
            for (0..std.math.divCeil(usize, rest, block_length) catch unreachable) |j| {
                buf[j * block_length ..][0..block_length].* = ks.nextBlock();
            }
            xorInto(dst[i..], src[i..], buf[0..rest]);
            const last_len = rest % block_length;
            if (last_len > 0) {
                ks.leftover = buf[rest - last_len ..][0..block_length].*;
                ks.leftover_len = block_length - last_len;
            }
        }

        /// Same as `xorBytes`, with the input and the output split into parts.
        /// Both sides must have the same total length, but they can be split at different places.
        fn xorParts(ks: *Self, dst: []const []u8, src: []const []const u8) void {
            var di: usize = 0;
            var si: usize = 0;
            var d: []u8 = &.{};
            var s: []const u8 = &.{};
            while (true) {
                while (d.len == 0 and di < dst.len) : (di += 1) d = dst[di];
                while (s.len == 0 and si < src.len) : (si += 1) s = src[si];
                if (d.len == 0 or s.len == 0) break;
                const n = @min(d.len, s.len);
                ks.xorBytes(d[0..n], s[0..n]);
                d = d[n..];
                s = s[n..];
            }
            assert(d.len == 0 and s.len == 0);
        }
    };
}

fn totalLength(parts: []const []const u8) usize {
    var len: usize = 0;
    for (parts) |part| len += part.len;
    return len;
}

fn xorInto(dst: []u8, a: []const u8, b: []const u8) void {
    for (dst, a, b) |*d, x, y| d.* = x ^ y;
}

fn xor(a: anytype, b: @TypeOf(a)) @TypeOf(a) {
    var r = a;
    for (&r, b) |*p, x| p.* ^= x;
    return r;
}

/// Multiplication by x in the POLYVAL field.
fn mulX(a: Block) Block {
    const v = mem.readInt(u128, &a, .little);
    const reduction = (0xc2 << 120) | 1;
    var r: Block = undefined;
    mem.writeInt(u128, &r, (v << 1) ^ (reduction & (0 -% (v >> 127))), .little);
    return r;
}

pub const AeadOptions = struct {
    frame_width: u64 = default_frame_width,
    nonce_length: usize = 16,
};

/// EtES-HCENC with the recommended frame width and a 16-byte nonce.
pub const EtesHcenc_128 = EtesHcenc(.{});

/// EtES-HCENC, authenticated encryption built from HCENC with the two-stage key derivation.
///
/// It adds 16 zero bytes after the first 32 bytes of the message, and decryption checks that they are still zero.
/// The ciphertext is 16 bytes longer than the message, and messages must be at least 32 bytes long.
///
/// It commits to the key, but only up to about 60 bits.
/// Use `UcxHcenc` for stronger commitment.
/// Reusing a nonce only reveals whether two messages with the same associated data are equal.
pub fn EtesHcenc(comptime options: AeadOptions) type {
    return Etes(.{ .frame_width = options.frame_width, .key_derivation = .two_stage }, options.nonce_length);
}

fn Etes(comptime mode_options: Options, comptime nonce_len: usize) type {
    const Mode = Hcenc(mode_options);

    return struct {
        const State = @This();

        mode: Mode,

        pub const key_length = Mode.key_length;
        pub const nonce_length = nonce_len;
        pub const ciphertext_expansion = block_length;
        pub const min_message_length = head_length;

        pub fn init(key: [key_length]u8) State {
            return .{ .mode = Mode.init(key) };
        }

        /// Encrypts `m` into `c`, which must be `ciphertext_expansion` bytes longer.
        /// The buffers must not overlap.
        ///
        /// Returns `error.InputTooShort` if `m` is shorter than `min_message_length`.
        pub fn encrypt(state: *const State, c: []u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8) !void {
            assert(c.len == m.len + ciphertext_expansion);
            if (m.len < min_message_length) return error.InputTooShort;
            const zeros: Block = @splat(0);
            state.mode.crypt(.encrypt, c[0..head_length], &.{c[head_length..]}, m[0..head_length].*, &.{ &zeros, m[head_length..] }, &.{ &npub, ad });
        }

        /// Decrypts `c` into `m`, which must be `ciphertext_expansion` bytes shorter.
        /// The buffers must not overlap.
        ///
        /// Returns `error.AuthenticationFailed` if the ciphertext is not valid, and clears `m`.
        pub fn decrypt(state: *const State, m: []u8, c: []const u8, ad: []const u8, npub: [nonce_length]u8) !void {
            errdefer crypto.secureZero(u8, m);
            if (c.len < min_message_length + ciphertext_expansion) return error.AuthenticationFailed;
            assert(m.len == c.len - ciphertext_expansion);
            try state.decryptParts(m, c[0..head_length].*, &.{c[head_length..]}, &.{ &npub, ad });
        }

        fn decryptParts(state: *const State, m: []u8, src_head: [head_length]u8, src_tail: []const []const u8, tweak: []const []const u8) !void {
            var tag: Block = undefined;
            state.mode.crypt(.decrypt, m[0..head_length], &.{ &tag, m[head_length..] }, src_head, src_tail, tweak);
            if (!crypto.timing_safe.eql(Block, tag, @splat(0))) return error.AuthenticationFailed;
        }
    };
}

/// How the UCX concealer gets its key.
pub const ConcealerKeying = enum {
    /// A fixed key, which commits to the key (CMT-1).
    er,
    /// A key computed from the nonce and the associated data, which commits to everything (CMT-4).
    her,
};

/// UCX-HCENC that commits to the key, with 116 bits of security.
pub const UcxHcenc_Cmt1 = UcxHcenc(.er, .{});

/// UCX-HCENC that commits to the key, the nonce, the associated data and the message, with 116 bits of security.
pub const UcxHcenc_Cmt4 = UcxHcenc(.her, .{});

/// UCX-HCENC, authenticated encryption that commits to the key, and optionally to all the inputs.
///
/// It encrypts with EtES-HCENC, then runs the last 127 bits of the ciphertext through two AES-256 calls.
/// The master key is an AES-256 key, and the ciphertext is 32 bytes longer than the message.
/// Messages must be at least 32 bytes long.
///
/// Each message costs two AES-256 calls on top of HCENC, and with `.her` also a KMAC256 and an AES-256 key schedule.
/// Reusing a nonce only reveals whether two messages with the same associated data are equal.
pub fn UcxHcenc(comptime keying: ConcealerKeying, comptime options: AeadOptions) type {
    const Base = Etes(.{ .frame_width = options.frame_width, .key_derivation = .one_call }, options.nonce_length);

    return struct {
        const State = @This();

        base: Base,
        concealer: switch (keying) {
            .er => Aes256EncryptCtx,
            .her => KMac256,
        },

        pub const key_length = 32;
        pub const nonce_length = options.nonce_length;
        pub const ciphertext_expansion = Base.ciphertext_expansion + block_length;
        pub const min_message_length = head_length;

        pub fn init(key: [key_length]u8) State {
            var derived: [4 * block_length]u8 = @splat(0);
            for (0..4) |i| derived[i * block_length] = @intCast(i);
            Aes256.initEnc(key).encryptWide(4, &derived, &derived);
            const kc = derived[0..32];
            const ke = derived[32..64];
            return .{
                .base = Base.init(ke.*),
                .concealer = switch (keying) {
                    .er => Aes256.initEnc(kc.*),
                    .her => KMac256.init(kc),
                },
            };
        }

        /// Encrypts `m` into `c`, which must be `ciphertext_expansion` bytes longer.
        /// The buffers must not overlap.
        ///
        /// Returns `error.InputTooShort` if `m` is shorter than `min_message_length`.
        pub fn encrypt(state: *const State, c: []u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8) !void {
            assert(c.len == m.len + ciphertext_expansion);
            const k = m.len + Base.ciphertext_expansion;
            try state.base.encrypt(c[0..k], m, ad, npub);

            // The first bit of the last 16 bytes stays, and the 127 bits after it are replaced with the 255 bits of the concealer.
            const window = c[k - block_length ..][0..32];
            const last = mem.readInt(u128, window[0..block_length], .little);
            const ctx = state.concealerCtx(ad, npub);
            const a, const b = feistel(&ctx, @truncate(last >> 1));
            mem.writeInt(u256, window, (last & 1) | (@as(u256, a) << 1) | (@as(u256, b) << 129), .little);
        }

        /// Decrypts `c` into `m`, which must be `ciphertext_expansion` bytes shorter.
        /// The buffers must not overlap.
        ///
        /// Returns `error.AuthenticationFailed` if the ciphertext is not valid, and clears `m`.
        pub fn decrypt(state: *const State, m: []u8, c: []const u8, ad: []const u8, npub: [nonce_length]u8) !void {
            errdefer crypto.secureZero(u8, m);
            if (c.len < min_message_length + ciphertext_expansion) return error.AuthenticationFailed;
            assert(m.len == c.len - ciphertext_expansion);
            const k = c.len - block_length;
            const window = mem.readInt(u256, c[k - block_length ..][0..32], .little);
            const ctx = state.concealerCtx(ad, npub);
            const d = feistelInverse(&ctx, @truncate(window >> 1), @truncate(window >> 129)) orelse return error.AuthenticationFailed;
            var last: Block = undefined;
            mem.writeInt(u128, &last, @as(u1, @truncate(window)) | (@as(u128, d) << 1), .little);
            const body = c[0 .. k - block_length];
            try state.base.decryptParts(m, c[0..head_length].*, &.{ body[head_length..], &last }, &.{ &npub, ad });
        }

        fn concealerCtx(state: *const State, ad: []const u8, npub: [nonce_length]u8) Aes256EncryptCtx {
            switch (keying) {
                .er => return state.concealer,
                .her => {
                    var kmac = state.concealer;
                    kmac.update(&npub);
                    kmac.update(ad);
                    var kappa: [32]u8 = undefined;
                    kmac.final(&kappa);
                    return Aes256.initEnc(kappa);
                },
            }
        }
    };
}

const top_bit: u128 = 1 << 127;

fn daviesMeyer(ctx: *const Aes256EncryptCtx, x: u128) u128 {
    var block: Block = undefined;
    mem.writeInt(u128, &block, x, .little);
    ctx.encrypt(&block, &block);
    return mem.readInt(u128, &block, .little) ^ x;
}

/// The paper's Feistel concealer, which turns 127 bits into A (128 bits) and B (127 bits).
fn feistel(ctx: *const Aes256EncryptCtx, d: u127) struct { u128, u127 } {
    const x: u128 = d;
    const b: u127 = @truncate(daviesMeyer(ctx, x));
    const a = daviesMeyer(ctx, b | top_bit) ^ x;
    return .{ a, b };
}

/// Returns null if A and B didn't come from `feistel` under this key.
fn feistelInverse(ctx: *const Aes256EncryptCtx, a: u128, b: u127) ?u127 {
    const x = a ^ daviesMeyer(ctx, b | top_bit);
    const r = b ^ @as(u127, @truncate(daviesMeyer(ctx, x & ~top_bit)));
    if ((x & top_bit) | r != 0) return null;
    return @truncate(x);
}

const testing = std.testing;

fn sequence(comptime n: usize) [n]u8 {
    var bytes: [n]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i);
    return bytes;
}

/// Equation (2) of the paper, one block at a time.
fn naiveKeystream(comptime w: u64, key: Block, mask: Block, out: []u8) void {
    const ctx = Aes128.initEnc(key);
    var j: usize = 0;
    while (j * block_length < out.len) : (j += 1) {
        var anchor = mask;
        var leaf = mask;
        const anchor_counter = mem.readInt(u64, anchor[0..8], .little) ^ ((w + 1) * (j / w));
        const leaf_counter = mem.readInt(u64, leaf[0..8], .little) ^ (j + j / w + 1);
        mem.writeInt(u64, anchor[0..8], anchor_counter, .little);
        mem.writeInt(u64, leaf[0..8], leaf_counter, .little);
        ctx.encrypt(&anchor, &anchor);
        ctx.encrypt(&leaf, &leaf);
        const n = @min(block_length, out.len - j * block_length);
        xorInto(out[j * block_length ..][0..n], anchor[0..n], leaf[0..n]);
    }
}

test "keystream matches the paper for any frame width, in one call or in pieces" {
    const key = sequence(16);
    const mask: Block = @as([8]u8, @splat(0xa5)) ++ @as([8]u8, @splat(0x3c));
    var expected: [1000]u8 = undefined;
    var actual: [1000]u8 = undefined;
    const zeros: [1000]u8 = @splat(0);
    inline for (.{ 1, 2, 3, 5, 6, 7, 8, 13, 4096 }) |w| {
        for ([_]usize{ 1, 15, 16, 17, 96, 97, 200, 1000 }) |len| {
            naiveKeystream(w, key, mask, expected[0..len]);
            for ([_]usize{ 1000, 1, 5, 16, 33, 100 }) |step| {
                var ks = Keystream(w).init(key, mask);
                var i: usize = 0;
                while (i < len) : (i += step) {
                    const n = @min(step, len - i);
                    ks.xorBytes(actual[i..][0..n], zeros[i..][0..n]);
                }
                try testing.expectEqualSlices(u8, expected[0..len], actual[0..len]);
            }
        }
    }
}

test "HCENC round trips in place" {
    const message = sequence(300);
    var buf: [300]u8 = undefined;
    var out: [300]u8 = undefined;
    inline for (.{ Hcenc_128, Hcenc(.{ .frame_width = 1, .key_derivation = .two_stage }) }) |Mode| {
        const cipher = Mode.init(sequence(32));
        for ([_]usize{ 32, 33, 47, 48, 100, 128, 300 }) |len| {
            for ([_][]const u8{ "", &sequence(33) }) |tweak| {
                try cipher.encrypt(out[0..len], message[0..len], tweak);
                @memcpy(buf[0..len], message[0..len]);
                try cipher.encrypt(buf[0..len], buf[0..len], tweak);
                try testing.expectEqualSlices(u8, out[0..len], buf[0..len]);
                try cipher.decrypt(buf[0..len], buf[0..len], tweak);
                try testing.expectEqualSlices(u8, message[0..len], buf[0..len]);
            }
        }
        try testing.expectError(error.InputTooShort, cipher.encrypt(out[0..31], message[0..31], ""));
        try testing.expectError(error.InputTooShort, cipher.decrypt(out[0..31], message[0..31], ""));
    }
}

test "AEAD modes round trip and reject forgeries" {
    inline for (.{ EtesHcenc_128, EtesHcenc(.{ .frame_width = 2, .nonce_length = 12 }), UcxHcenc_Cmt1, UcxHcenc_Cmt4 }) |Aead| {
        const aead = Aead.init(sequence(32));
        const nonce = sequence(Aead.nonce_length);
        var other_nonce = nonce;
        other_nonce[0] ^= 1;
        const message = sequence(300);
        var c: [300 + Aead.ciphertext_expansion]u8 = undefined;
        var m: [300]u8 = undefined;
        for ([_]usize{ 32, 33, 48, 63, 100, 300 }) |len| {
            const ct = c[0 .. len + Aead.ciphertext_expansion];
            try aead.encrypt(ct, message[0..len], "ad", nonce);
            try aead.decrypt(m[0..len], ct, "ad", nonce);
            try testing.expectEqualSlices(u8, message[0..len], m[0..len]);

            for ([_]usize{ 0, 32, 47, ct.len - 17, ct.len - 16, ct.len - 1 }) |pos| {
                ct[pos] ^= 0x80;
                try testing.expectError(error.AuthenticationFailed, aead.decrypt(m[0..len], ct, "ad", nonce));
                try testing.expect(mem.allEqual(u8, m[0..len], 0));
                ct[pos] ^= 0x80;
            }
            try testing.expectError(error.AuthenticationFailed, aead.decrypt(m[0..len], ct, "", nonce));
            try testing.expectError(error.AuthenticationFailed, aead.decrypt(m[0..len], ct, "ad", other_nonce));
        }
        try testing.expectError(error.InputTooShort, aead.encrypt(c[0 .. 31 + Aead.ciphertext_expansion], message[0..31], "", nonce));
        @memset(&m, 0xaa);
        try testing.expectError(error.AuthenticationFailed, aead.decrypt(m[0..31], c[0 .. 31 + Aead.ciphertext_expansion], "", nonce));
        try testing.expect(mem.allEqual(u8, m[0..31], 0));
    }
}

fn expectMode(comptime Mode: type, tweak: []const u8, comptime ciphertext_hex: []const u8) !void {
    const message = sequence(ciphertext_hex.len / 2);
    var expected: [message.len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, ciphertext_hex);
    const cipher = Mode.init(sequence(32));
    var buf: [message.len]u8 = undefined;
    try cipher.encrypt(&buf, &message, tweak);
    try testing.expectEqualSlices(u8, &expected, &buf);
    try cipher.decrypt(&buf, &buf, tweak);
    try testing.expectEqualSlices(u8, &message, &buf);
}

fn expectAead(comptime Aead: type, ad: []const u8, comptime ciphertext_hex: []const u8) !void {
    const message = sequence(ciphertext_hex.len / 2 - Aead.ciphertext_expansion);
    var expected: [ciphertext_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, ciphertext_hex);
    const aead = Aead.init(sequence(32));
    const nonce: [16]u8 = sequence(0x50)[0x40..].*;
    var c: [expected.len]u8 = undefined;
    try aead.encrypt(&c, &message, ad, nonce);
    try testing.expectEqualSlices(u8, &expected, &c);
    var m: [message.len]u8 = undefined;
    try aead.decrypt(&m, &c, ad, nonce);
    try testing.expectEqualSlices(u8, &message, &m);
}

test "known answers" {
    // Computed with an independent Python implementation of the paper.
    // The key is 00 01 02 ... 1f, the message is 00 01 02 ..., and the AEAD nonce is 40 41 ... 4f.
    const tweak17: [17]u8 = sequence(117)[100..].*;
    try expectMode(Hcenc_128, "", "398e436b918bad34189ed9393ab8de1ca6c878cb860b0fc44f2981c109bc571f");
    try expectMode(Hcenc_128, "", "c97bb9ae0f5a06884715e3f7409008d425c336bd21f763f50b1aa936c48ddad640");
    try expectMode(Hcenc_128, "", "885642823b4b2df9c7756abb8a0b3ca95a17aff851fb72b6e2e330279b146ee0a21f9d578e94f6a79474e52912717bc28b81bc98ffb94b7bf3f888003f3674b4291e6c8ade154b02a8cea10e0a6697ae56cdd111d0374d6cba43225ad7fa2a7c10d69642");
    try expectMode(Hcenc(.{ .frame_width = 1 }), &tweak17, "b343094e64706207a26c7163034f6e43fd5d0f366ad54e4a03d740717ecfdf91e1231f0d71fd7cdf9523b9e36742185b8820df78f48a7a4eca261e6f3fb13c1804c4d1049f57fb5a9de97740330627f67c37bb6cb6fc7b5e2f65ea35aad5282e4730c3d83c29d12496f18377d668aef25e47453f5e0814273324e6caaa614e8fc3e2ee49d20f27914f40bb7783eb858a381fb5d84faed61e115de9bda30525090c30d61df9d4e2492da08d174152717ea9faa3a011243228e63b4f0b4798ee053285f6a41747db61efb20079f60d259844166d0d8a921e5639bfbedc0abcd98a6cb36bc76624b221575bede5112d51e3c8cd03b36ff801ae6656cb518c9900");
    try expectMode(Hcenc(.{ .key_derivation = .two_stage }), "tweak", "3e367781de0ce586a02275ae60b22ea264a3704704b8e6f4cd26e533f5547f5508a24d1a581668bdd05a586d6fe2094b7c9f30a6e548da896594c724a4e0ac");
    try expectMode(Hcenc(.{ .frame_width = 3, .key_derivation = .two_stage }), "tweak", "8cc07aa176898e307218b2a19b9d904159aa8e4219312b6001eaefff0132e19f0b950eeb1c74e227b83bd735af7687b5f79231cb44f4a5cf8da3407a395c763a310be69f89f6153056036a6f7e8f7f4e4d9870d97fa1d082014dc269442b8c449ad231a64d2c8ac226dbad38733f82007482cf34796bd741281aef26fbda935bdad407824f3ba37c7546ea506e816f899cc8ab41d56a6ebeff5565970936d918ad2ae9681bb7f3b698921b09262eaa72e5cf399b1b7fc1d75e16942a0af6af8b1bbea15561");
    try expectAead(EtesHcenc_128, "", "aa8271dce4da49f52a74790add3ef96f43572fd4b3bc291b6f0059dc54dd0d6950e86292822d20ed49c171694e504fb7");
    try expectAead(EtesHcenc_128, "ad", "231a3c6e669c870af54ade681b1dc208cf3bbb430754c47653c8ab52a818b8078ff462de3e8616950b07252f705bc4ae82d45919012cd569fa8b4b337a47b9959db6cd33cdf5009ce4a0f104d846cde9eeb5ff6f644d3e103e9f6c02bf494ec6bb5e9a2831b9abd3baefe2e0eb3cb0452ee6d787");
    try expectAead(UcxHcenc_Cmt1, "", "d3b0528f62d1c20d620db67fcc6665e8d5c3da61bee744f982d6913ef7e6b0e5b8dda4c079ec735f0ff1ae834821d653423713e3206482f80fb43b1d9caa6088");
    try expectAead(UcxHcenc_Cmt1, "associated data", "bef202ab397690c4611ff1c1e1facdd0f71e0a5844eb86ea569946beab1a5281a88971fa0ecfe24ed1c9e42b27c12cbfe733ef81da9669c30a590379f272d165b9de509d4971395a38b655a513fb3e66c99068078ca438bde85522ab559adafac78ae87e1a9c54bad560ad85157b1064f4284cb96de27321c30e5ea468f58ead51218e1261895e3b563876fba5b116576010cecacc7c420ec76955559682ae78cd82a36f76d964076ba6afbd50631c329d2438f314c8dd1ff801ffbabd9675f5f0bab03f6932c4412b6787314833f8b0ed40a75cc6fd2cf1dda40062482a3c6b6cc8e744be813177f2b13e4d4233d8fbd1e735acf691ec6e97db3abfe1eb9c420fe0944270376cb9b136661f0c9ac611b1c1de6e107e7150d4743da1df09e4");
    try expectAead(UcxHcenc_Cmt4, "", "8a5cb7ee0cfd33cd3e320addaf5d40ee1d7707a08d2a81e4139ff6b3b92be15c5a345691c87bc9d5f4f673d6f17c641490a40814b28a5d0ed29a569bdc5e4e98b4");
    try expectAead(UcxHcenc_Cmt4, "associated data", "3808405a13f34e40aeddeb862eeccc6108e264f317388802a92c4b0a909331540712b2033130952726ae000269dbc04f368169943babffb9593b91d7f9c274825867aefdca52b6b5569f52012ad35bbb19f76ec7c906d3de8b6fc61b110594f2f01bf9da05159a9663016f8e41e3b9da4b1324092134aea4369b1937a58f4a250f04a28e");
}
