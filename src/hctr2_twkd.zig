const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = crypto.onetimeauth.Polyval;
const hctr2_mod = @import("hctr2.zig");

/// HCTR2-TwKD (Tweak-Based Key Derivation) with AES-128 and CENC KDF.
/// Achieves 2n/3-bit security when BC calls per tweak ≤ 2^(n/3).
pub const Hctr2TwKD_128 = Hctr2TwKD(aes.Aes128, CencKdf(aes.Aes128));

/// HCTR2-TwKD (Tweak-Based Key Derivation) with AES-256 and CENC KDF.
/// Achieves 2n/3-bit security when BC calls per tweak ≤ 2^(n/3).
pub const Hctr2TwKD_256 = Hctr2TwKD(aes.Aes256, CencKdf(aes.Aes256));

/// CENC-based Key Derivation Function.
///
/// Derives an AES key from a master key and a tweak using CENC construction:
/// For AES-128: K = E_L(00||T) ⊕ E_L(01||T)
/// For AES-256: K = (E_L(00||T) ⊕ E_L(01||T)) || (E_L(00||T) ⊕ E_L(10||T))
///
/// This provides beyond-birthday-bound security when the same tweak
/// is not used more than approximately 2^(n/3) times.
pub fn CencKdf(comptime Aes: anytype) type {
    const AesEncryptCtx = aes.AesEncryptCtx(Aes);
    const aes_block_length = 16;
    const derived_key_length = Aes.key_bits / 8;

    return struct {
        const Self = @This();

        ks: AesEncryptCtx,

        /// Master key length (same as AES key length).
        pub const master_key_length = Aes.key_bits / 8;

        /// Derived key length (same as AES key length).
        pub const key_length = derived_key_length;

        /// Maximum tweak length (126 bits = 15 bytes + 6 bits, but we use 14 bytes for simplicity).
        pub const max_tweak_length = 14;

        /// Initialize the KDF with a master key.
        pub fn init(master_key: [master_key_length]u8) Self {
            return Self{
                .ks = Aes.initEnc(master_key),
            };
        }

        /// Derive a key from a tweak.
        ///
        /// Parameters:
        /// - `tweak`: Tweak value (max 14 bytes)
        ///
        /// Returns: Derived AES key.
        pub fn deriveKey(self: *const Self, tweak: []const u8) [key_length]u8 {
            assert(tweak.len <= max_tweak_length);

            // Prepare blocks with prefix || tweak || padding
            // Block format: [2-bit prefix][126-bit tweak space]
            // We use: [1 byte prefix][14 bytes tweak][1 byte padding]
            var block0: [aes_block_length]u8 = @splat(0);
            var block1: [aes_block_length]u8 = @splat(0);

            // Set prefix bytes (00 and 01 for first 128 bits)
            block0[0] = 0x00;
            block1[0] = 0x01;

            // Copy tweak to both blocks (starting at byte 1)
            @memcpy(block0[1..][0..tweak.len], tweak);
            @memcpy(block1[1..][0..tweak.len], tweak);

            // Encrypt blocks
            var enc0: [aes_block_length]u8 = undefined;
            var enc1: [aes_block_length]u8 = undefined;
            self.ks.encrypt(&enc0, &block0);
            self.ks.encrypt(&enc1, &block1);

            // First half of derived key: E(00||T) ⊕ E(01||T)
            var derived: [key_length]u8 = undefined;
            for (derived[0..aes_block_length], enc0, enc1) |*d, e0, e1| {
                d.* = e0 ^ e1;
            }

            // For 256-bit keys, derive second half
            if (key_length > aes_block_length) {
                var block2: [aes_block_length]u8 = @splat(0);
                block2[0] = 0x02; // Prefix 10 (binary)
                @memcpy(block2[1..][0..tweak.len], tweak);

                var enc2: [aes_block_length]u8 = undefined;
                self.ks.encrypt(&enc2, &block2);

                // Second half: E(00||T) ⊕ E(10||T)
                for (derived[aes_block_length..], enc0, enc2) |*d, e0, e2| {
                    d.* = e0 ^ e2;
                }
            }

            return derived;
        }
    };
}

/// HCTR2-TwKD (HCTR2 with Tweak-Based Key Derivation) is a beyond-birthday-bound
/// secure wide-block tweakable cipher.
///
/// HCTR2-TwKD achieves 2n/3-bit multi-user security (approximately 85 bits with
/// 128-bit blocks) when the number of BC calls per tweak is bounded by 2^(n/3).
///
/// Construction (from "Beyond-Birthday-Bound Security with HCTR2", ASIACRYPT 2025):
/// - Uses a KDF F to derive HCTR2's key from the tweak
/// - HCTR2-TwKD[F_L, E, H](T, M) = HCTR2[E_{F_L(T_0)}, H](T_*, M)
/// - Cost per block: 1 BC call + 2 field multiplications (same as HCTR2)
/// - Small overhead for key derivation per unique tweak
///
/// Security properties:
/// - Beyond-birthday-bound: ~85-bit security when tweak repetition ≤ 2^(n/3)
/// - Multi-user secure
/// - Ciphertext length equals plaintext length
/// - Maintains backward compatibility with HCTR2 implementations
///
/// Type parameters:
/// - `Aes`: AES variant (Aes128 or Aes256)
/// - `Kdf`: Key derivation function type
pub fn Hctr2TwKD(comptime Aes: anytype, comptime Kdf: anytype) type {
    const Hctr2 = hctr2_mod.Hctr2(Aes);
    const aes_block_length = 16;

    return struct {
        const State = @This();

        kdf: Kdf,

        /// Authentication tag length (0 - HCTR2-TwKD is unauthenticated).
        pub const tag_length = 0;

        /// Nonce length (0 - HCTR2-TwKD uses tweaks instead).
        pub const nonce_length = 0;

        /// Master key length in bytes.
        pub const key_length = Kdf.master_key_length;

        /// AES block length in bytes (always 16).
        pub const block_length = aes_block_length;

        /// Maximum tweak length for key derivation.
        pub const max_tweak_length = Kdf.max_tweak_length;

        /// Initialize HCTR2-TwKD cipher state from a master key.
        ///
        /// Parameters:
        /// - `key`: Master key for key derivation
        ///
        /// Returns: Initialized cipher state ready for encryption/decryption operations.
        pub fn init(key: [key_length]u8) State {
            return State{
                .kdf = Kdf.init(key),
            };
        }

        /// Encrypt plaintext to ciphertext using HCTR2-TwKD.
        ///
        /// The tweak is used for key derivation. Each unique tweak derives a unique
        /// HCTR2 key, providing beyond-birthday-bound security when the same tweak
        /// is not reused excessively (limit: ~2^42 encryptions per tweak).
        ///
        /// Parameters:
        /// - `state`: Initialized cipher state
        /// - `ciphertext`: Output buffer (must be same length as plaintext)
        /// - `plaintext`: Input data to encrypt (minimum 16 bytes)
        /// - `tweak`: Tweak value for key derivation (max 14 bytes)
        ///
        /// Returns: `error.InputTooShort` if plaintext is less than 16 bytes,
        ///          `error.TweakTooLong` if tweak exceeds max_tweak_length.
        pub fn encrypt(state: *const State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            if (tweak.len > max_tweak_length) {
                return error.TweakTooLong;
            }

            // Derive key from tweak
            const derived_key = state.kdf.deriveKey(tweak);

            // Initialize HCTR2 with derived key and encrypt
            // Use empty tweak for HCTR2 since tweak info is in the derived key
            var hctr2 = Hctr2.init(derived_key);
            try hctr2.encrypt(ciphertext, plaintext, &.{});
        }

        /// Decrypt ciphertext to plaintext using HCTR2-TwKD.
        ///
        /// Parameters:
        /// - `state`: Initialized cipher state
        /// - `plaintext`: Output buffer (must be same length as ciphertext)
        /// - `ciphertext`: Input data to decrypt (minimum 16 bytes)
        /// - `tweak`: Tweak value used during encryption (max 14 bytes)
        ///
        /// Returns: `error.InputTooShort` if ciphertext is less than 16 bytes,
        ///          `error.TweakTooLong` if tweak exceeds max_tweak_length.
        pub fn decrypt(state: *const State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            if (tweak.len > max_tweak_length) {
                return error.TweakTooLong;
            }

            // Derive key from tweak
            const derived_key = state.kdf.deriveKey(tweak);

            // Initialize HCTR2 with derived key and decrypt
            var hctr2 = Hctr2.init(derived_key);
            try hctr2.decrypt(plaintext, ciphertext, &.{});
        }

        /// Encrypt with split tweak: part for key derivation, part for HCTR2.
        ///
        /// This allows using a longer tweak by splitting it into:
        /// - `kdf_tweak`: Used for key derivation (max 14 bytes)
        /// - `hctr2_tweak`: Passed to underlying HCTR2 (any length)
        ///
        /// Use this when you need longer tweaks or want finer control over
        /// the tweak partitioning.
        pub fn encryptSplit(
            state: *const State,
            ciphertext: []u8,
            plaintext: []const u8,
            kdf_tweak: []const u8,
            hctr2_tweak: []const u8,
        ) !void {
            if (kdf_tweak.len > max_tweak_length) {
                return error.TweakTooLong;
            }

            const derived_key = state.kdf.deriveKey(kdf_tweak);
            var hctr2 = Hctr2.init(derived_key);
            try hctr2.encrypt(ciphertext, plaintext, hctr2_tweak);
        }

        /// Decrypt with split tweak.
        pub fn decryptSplit(
            state: *const State,
            plaintext: []u8,
            ciphertext: []const u8,
            kdf_tweak: []const u8,
            hctr2_tweak: []const u8,
        ) !void {
            if (kdf_tweak.len > max_tweak_length) {
                return error.TweakTooLong;
            }

            const derived_key = state.kdf.deriveKey(kdf_tweak);
            var hctr2 = Hctr2.init(derived_key);
            try hctr2.decrypt(plaintext, ciphertext, hctr2_tweak);
        }
    };
}

test "HCTR2-TwKD-128 encrypt/decrypt round-trip" {
    const key = [_]u8{0} ** 16;
    const state = Hctr2TwKD_128.init(key);

    const plaintext = "Hello, HCTR2-TwKD!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const tweak = "test tweak";

    try state.encrypt(&ciphertext, plaintext, tweak);
    try state.decrypt(&decrypted, &ciphertext, tweak);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "HCTR2-TwKD-256 encrypt/decrypt round-trip" {
    const key = [_]u8{0} ** 32;
    const state = Hctr2TwKD_256.init(key);

    const plaintext = "Hello, HCTR2-TwKD-256!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const tweak = "test tweak 256";

    try state.encrypt(&ciphertext, plaintext, tweak);
    try state.decrypt(&decrypted, &ciphertext, tweak);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "HCTR2-TwKD-128 minimum block size" {
    const key = [_]u8{0} ** 16;
    const state = Hctr2TwKD_128.init(key);

    const plaintext = [_]u8{0x42} ** 16;
    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    try state.encrypt(&ciphertext, &plaintext, "tweak");
    try state.decrypt(&decrypted, &ciphertext, "tweak");

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "HCTR2-TwKD-128 input too short" {
    const key = [_]u8{0} ** 16;
    const state = Hctr2TwKD_128.init(key);

    const plaintext = [_]u8{0x42} ** 15;
    var ciphertext: [15]u8 = undefined;

    try std.testing.expectError(error.InputTooShort, state.encrypt(&ciphertext, &plaintext, "tweak"));
}

test "HCTR2-TwKD-128 tweak too long" {
    const key = [_]u8{0} ** 16;
    const state = Hctr2TwKD_128.init(key);

    const plaintext = [_]u8{0x42} ** 16;
    var ciphertext: [16]u8 = undefined;

    // 15 bytes exceeds max_tweak_length of 14
    const long_tweak = [_]u8{0} ** 15;
    try std.testing.expectError(error.TweakTooLong, state.encrypt(&ciphertext, &plaintext, &long_tweak));
}

test "HCTR2-TwKD-128 different tweaks produce different ciphertexts" {
    const key = [_]u8{0} ** 16;
    const state = Hctr2TwKD_128.init(key);

    const plaintext = [_]u8{0x42} ** 32;
    var ciphertext1: [32]u8 = undefined;
    var ciphertext2: [32]u8 = undefined;

    try state.encrypt(&ciphertext1, &plaintext, "tweak1");
    try state.encrypt(&ciphertext2, &plaintext, "tweak2");

    try std.testing.expect(!std.mem.eql(u8, &ciphertext1, &ciphertext2));
}

test "HCTR2-TwKD-128 split tweak" {
    const key = [_]u8{0} ** 16;
    const state = Hctr2TwKD_128.init(key);

    const plaintext = "Test split tweak mode";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const kdf_tweak = "kdf part";
    const hctr2_tweak = "hctr2 part - can be longer than 14 bytes!";

    try state.encryptSplit(&ciphertext, plaintext, kdf_tweak, hctr2_tweak);
    try state.decryptSplit(&decrypted, &ciphertext, kdf_tweak, hctr2_tweak);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "HCTR2-TwKD-128 large message" {
    const key = [_]u8{0} ** 16;
    const state = Hctr2TwKD_128.init(key);

    const plaintext = [_]u8{0xAB} ** 1024;
    var ciphertext: [1024]u8 = undefined;
    var decrypted: [1024]u8 = undefined;

    try state.encrypt(&ciphertext, &plaintext, "large tweak");
    try state.decrypt(&decrypted, &ciphertext, "large tweak");

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "CENC KDF derives different keys for different tweaks" {
    const Kdf = CencKdf(aes.Aes128);
    const master_key = [_]u8{0} ** 16;
    const kdf = Kdf.init(master_key);

    const key1 = kdf.deriveKey("tweak1");
    const key2 = kdf.deriveKey("tweak2");

    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "CENC KDF deterministic" {
    const Kdf = CencKdf(aes.Aes128);
    const master_key = [_]u8{0} ** 16;
    const kdf = Kdf.init(master_key);

    const key1 = kdf.deriveKey("same tweak");
    const key2 = kdf.deriveKey("same tweak");

    try std.testing.expectEqualSlices(u8, &key1, &key2);
}

test "CENC KDF 256-bit key derivation" {
    const Kdf = CencKdf(aes.Aes256);
    const master_key = [_]u8{0} ** 32;
    const kdf = Kdf.init(master_key);

    const key = kdf.deriveKey("test");
    try std.testing.expect(key.len == 32);

    // Verify different tweaks produce different keys
    const key2 = kdf.deriveKey("test2");
    try std.testing.expect(!std.mem.eql(u8, &key, &key2));
}
