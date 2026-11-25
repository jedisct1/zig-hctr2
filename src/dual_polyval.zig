const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = std.crypto.onetimeauth.Polyval;

const block_length = 16;

const has_pmull = builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c and builtin.cpu.has(.aarch64, .aes);
const has_pclmul = builtin.cpu.arch == .x86_64 and builtin.zig_backend != .stage2_c and builtin.cpu.has(.x86, .pclmul) and builtin.cpu.has(.x86, .avx);

/// POLYVAL of the same input under two keys.
///
/// On CPUs with carryless multiplication, both hashes are computed in one pass, which is a lot faster than two separate ones.
/// Other CPUs use the standard library's POLYVAL twice.
pub const DualPolyval = if (has_pmull or has_pclmul) VectorDualPolyval else FallbackDualPolyval;

const FallbackDualPolyval = struct {
    p: [2]Polyval,

    pub fn init(key1: *const [block_length]u8, key2: *const [block_length]u8) FallbackDualPolyval {
        return .{ .p = .{ Polyval.init(key1), Polyval.init(key2) } };
    }

    pub fn hasher(keys: *const FallbackDualPolyval) Hasher {
        return .{ .p = keys.p };
    }

    pub const Hasher = struct {
        p: [2]Polyval,

        pub fn update(st: *Hasher, data: []const u8) void {
            st.p[0].update(data);
            st.p[1].update(data);
        }

        pub fn final(st: *Hasher) [2 * block_length]u8 {
            return st.p[0].finalResult() ++ st.p[1].finalResult();
        }
    };
};

const V = @Vector(2, u64);

inline fn clmulLo(a: V, b: V) V {
    if (has_pmull) {
        return asm (
            \\ pmull %[out].1q, %[a].1d, %[b].1d
            : [out] "=w" (-> V),
            : [a] "w" (a),
              [b] "w" (b),
        );
    } else {
        return asm (
            \\ vpclmulqdq $0x00, %[a], %[b], %[out]
            : [out] "=x" (-> V),
            : [a] "x" (a),
              [b] "x" (b),
        );
    }
}

inline fn clmulHi(a: V, b: V) V {
    if (has_pmull) {
        return asm (
            \\ pmull2 %[out].1q, %[a].2d, %[b].2d
            : [out] "=w" (-> V),
            : [a] "w" (a),
              [b] "w" (b),
        );
    } else {
        return asm (
            \\ vpclmulqdq $0x11, %[a], %[b], %[out]
            : [out] "=x" (-> V),
            : [a] "x" (a),
              [b] "x" (b),
        );
    }
}

inline fn swap(a: V) V {
    return @shuffle(u64, a, undefined, [2]i32{ 1, 0 });
}

inline fn load(bytes: *const [block_length]u8) V {
    const p: *align(1) const V = @ptrCast(bytes);
    return p.*;
}

/// A power of a key, plus the XOR of its two halves that Karatsuba needs.
const Power = struct {
    h: V,
    k: V,

    fn init(h: V) Power {
        return .{ .h = h, .k = h ^ swap(h) };
    }
};

/// A product before reduction, so that several of them can be added up and reduced only once.
const Product = struct {
    lo: V,
    hi: V,
    mid: V,

    inline fn init(x: V, xk: V, p: Power) Product {
        return .{ .lo = clmulLo(x, p.h), .hi = clmulHi(x, p.h), .mid = clmulLo(xk, p.k) };
    }

    inline fn add(acc: *Product, x: V, xk: V, p: Power) void {
        acc.lo ^= clmulLo(x, p.h);
        acc.hi ^= clmulHi(x, p.h);
        acc.mid ^= clmulLo(xk, p.k);
    }

    /// Reduces modulo the POLYVAL polynomial, including its division by x^128.
    inline fn reduce(prod: Product) V {
        const mid = prod.mid ^ prod.lo ^ prod.hi;
        const lo = prod.lo ^ @shuffle(u64, mid, V{ 0, 0 }, [2]i32{ -1, 0 });
        const hi = prod.hi ^ @shuffle(u64, mid, V{ 0, 0 }, [2]i32{ 1, -1 });
        const poly: V = .{ 0xc200000000000000, 0 };
        const t = swap(lo) ^ clmulLo(lo, poly);
        return hi ^ swap(t) ^ clmulLo(t, poly);
    }
};

fn dot(a: V, b: V) V {
    return Product.init(a, a ^ swap(a), Power.init(b)).reduce();
}

const VectorDualPolyval = struct {
    const aggregate = 16;

    /// powers[k][i] is key k to the power i + 1.
    powers: [2][aggregate]Power,

    pub fn init(key1: *const [block_length]u8, key2: *const [block_length]u8) VectorDualPolyval {
        var keys: VectorDualPolyval = undefined;
        for (&keys.powers, [_]*const [block_length]u8{ key1, key2 }) |*powers, key| {
            const h = load(key);
            var p = h;
            for (powers) |*power| {
                power.* = .init(p);
                p = dot(p, h);
            }
        }
        return keys;
    }

    pub fn hasher(keys: *const VectorDualPolyval) Hasher {
        return .{ .powers = &keys.powers };
    }

    pub const Hasher = struct {
        powers: *const [2][aggregate]Power,
        acc: [2]V = .{ @splat(0), @splat(0) },
        buffered: usize = 0,
        buf: [aggregate * block_length]u8 = undefined,

        /// Absorbs `n` blocks with a single reduction for each key.
        fn absorb(st: *Hasher, n: usize, input: []const u8) void {
            assert(n >= 1 and n <= aggregate and input.len == n * block_length);
            var x: [aggregate]V = undefined;
            var xk: [aggregate]V = undefined;
            for (0..n) |i| {
                x[i] = load(input[i * block_length ..][0..block_length]);
                xk[i] = x[i] ^ swap(x[i]);
            }
            inline for (0..2) |k| {
                const powers = &st.powers[k];
                const first = x[0] ^ st.acc[k];
                var prod = Product.init(first, first ^ swap(first), powers[n - 1]);
                for (1..n) |i| prod.add(x[i], xk[i], powers[n - 1 - i]);
                st.acc[k] = prod.reduce();
            }
        }

        /// Small inputs are buffered, so that a run of short updates only costs one reduction.
        pub fn update(st: *Hasher, data: []const u8) void {
            var m = data;
            if (st.buffered > 0) {
                const n = @min(st.buf.len - st.buffered, m.len);
                @memcpy(st.buf[st.buffered..][0..n], m[0..n]);
                st.buffered += n;
                m = m[n..];
                if (st.buffered < st.buf.len) return;
                st.absorb(aggregate, &st.buf);
                st.buffered = 0;
            }
            while (m.len >= st.buf.len) : (m = m[st.buf.len..]) {
                st.absorb(aggregate, m[0..st.buf.len]);
            }
            @memcpy(st.buf[0..m.len], m);
            st.buffered = m.len;
        }

        /// Returns both hashes.
        /// The input must be a whole number of blocks.
        pub fn final(st: *Hasher) [2 * block_length]u8 {
            assert(st.buffered % block_length == 0);
            if (st.buffered > 0) st.absorb(st.buffered / block_length, st.buf[0..st.buffered]);
            return @as([block_length]u8, @bitCast(st.acc[0])) ++ @as([block_length]u8, @bitCast(st.acc[1]));
        }
    };
};

test "matches the standard POLYVAL" {
    var key1: [16]u8 = undefined;
    var key2: [16]u8 = undefined;
    var data: [2000]u8 = undefined;
    for (&key1, &key2, 0..) |*a, *b, i| {
        a.* = @truncate(i *% 7 +% 1);
        b.* = @truncate(i *% 13 +% 200);
    }
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 31 +% 5);
    const keys = DualPolyval.init(&key1, &key2);

    for ([_]usize{ 0, 16, 32, 112, 128, 144, 240, 256, 272, 512, 1008, 2000 }) |len| {
        for ([_]usize{ 1, 7, 16, 100, 1000 }) |step| {
            var st = keys.hasher();
            var i: usize = 0;
            while (i < len) : (i += step) st.update(data[i..@min(i + step, len)]);
            var expected: [32]u8 = undefined;
            Polyval.create(expected[0..16], data[0..len], &key1);
            Polyval.create(expected[16..32], data[0..len], &key2);
            try std.testing.expectEqualSlices(u8, &expected, &st.final());
        }
    }
}
