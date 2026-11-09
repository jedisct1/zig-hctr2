const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const mem = std.mem;
const assert = std.debug.assert;
const Polyval = crypto.onetimeauth.Polyval;
const hctr2_mod = @import("hctr2.zig");

/// HCTR2-TwKD (Tweak-Based Key Derivation) with AES-128 and CENC KDF.
///
/// Every new T0 is one more AES-128 key an attacker can go after.
/// Use the AES-256 version if you expect more than about 2^43 different T0 values.
pub const Hctr2TwKD_128 = Hctr2TwKD(aes.Aes128, CencKdf(aes.Aes128));

/// HCTR2-TwKD (Tweak-Based Key Derivation) with AES-256 and CENC KDF.
pub const Hctr2TwKD_256 = Hctr2TwKD(aes.Aes256, CencKdf(aes.Aes256));

/// CENC key derivation.
///
/// Turns a master key and a 126-bit tweak T into an AES key:
/// For AES-128: K = E_L(00||T) XOR E_L(01||T)
/// For AES-256: K = (E_L(00||T) XOR E_L(01||T)) || (E_L(00||T) XOR E_L(10||T))
///
/// The paper only defines the AES-256 version.
/// The AES-128 version is our own: same idea, using AES-128 and deriving 16 bytes instead of 32.
///
/// T is stored in 16 bytes, and the top two bits of the first byte must be zero.
/// Those two bits are where the 00/01/10 prefix goes.
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

        /// Tweak length in bytes (126 bits packed into 16 bytes).
        pub const tweak_length = 16;
        pub const tweak_bits = 126;

        /// Initialize the KDF with a master key.
        pub fn init(master_key: [master_key_length]u8) Self {
            return Self{
                .ks = Aes.initEnc(master_key),
            };
        }

        /// Derive a key from a tweak.
        ///
        /// Parameters:
        /// - `tweak`: 126-bit tweak encoded in 16 bytes (top 2 bits of first byte must be zero)
        ///
        /// Returns: Derived AES key.
        pub fn deriveKey(self: *const Self, tweak: []const u8) [key_length]u8 {
            assert(validateTweak(tweak));

            var block0 = makeBlock(tweak, 0);
            var block1 = makeBlock(tweak, 1);

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
                var block2 = makeBlock(tweak, 2);

                var enc2: [aes_block_length]u8 = undefined;
                self.ks.encrypt(&enc2, &block2);

                // Second half: E(00||T) ⊕ E(10||T)
                for (derived[aes_block_length..], enc0, enc2) |*d, e0, e2| {
                    d.* = e0 ^ e2;
                }
            }

            return derived;
        }

        pub fn validateTweak(tweak: []const u8) bool {
            return tweak.len == tweak_length and (tweak[0] & 0xC0) == 0;
        }

        fn makeBlock(tweak: []const u8, prefix: u8) [aes_block_length]u8 {
            assert(prefix <= 2);
            var block: [aes_block_length]u8 = undefined;
            @memcpy(block[0..], tweak);
            block[0] = (block[0] & 0x3F) | (prefix << 6);
            return block;
        }
    };
}

/// A length-preserving wide-block tweakable cipher that derives its HCTR2 key from the tweak.
///
/// The first part of the tweak, T0, picks the HCTR2 key through a KDF.
/// The rest, T*, goes to a regular HCTR2.
/// From "Beyond-Birthday-Bound Security with HCTR2", ASIACRYPT 2025.
///
/// Each block costs the same as HCTR2, plus one key derivation per message.
///
/// You get about 85 bits of multi-user security as long as each user processes at most about 2^42 blocks with the same T0.
/// Tweak blocks and decryption count too.
/// Changing only T* does not help, because it does not affect the key.
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

        /// How many bytes at the start of the tweak go to the KDF.
        pub const kdf_tweak_length = Kdf.tweak_length;

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

        /// Encrypts `plaintext` with `tweak` into `ciphertext`.
        ///
        /// The first `kdf_tweak_length` bytes of the tweak are T0, which picks the key.
        /// The rest is T*, which goes to HCTR2.
        ///
        /// Returns `error.InputTooShort`, `error.TweakTooShort` or `error.InvalidTweak` on bad input.
        pub fn encrypt(state: *const State, ciphertext: []u8, plaintext: []const u8, tweak: []const u8) !void {
            if (tweak.len < kdf_tweak_length) {
                return error.TweakTooShort;
            }

            const kdf_tweak = tweak[0..kdf_tweak_length];
            if (!validateKdfTweak(kdf_tweak)) {
                return error.InvalidTweak;
            }

            // Derive key from T0
            const derived_key = state.kdf.deriveKey(kdf_tweak);

            // Initialize HCTR2 with derived key and encrypt
            // Pass T* as the HCTR2 tweak
            var hctr2 = Hctr2.init(derived_key);
            try hctr2.encrypt(ciphertext, plaintext, tweak[kdf_tweak_length..]);
        }

        /// Decrypt ciphertext to plaintext using HCTR2-TwKD.
        ///
        /// Parameters:
        /// - `state`: Initialized cipher state
        /// - `plaintext`: Output buffer (must be same length as ciphertext)
        /// - `ciphertext`: Input data to decrypt (minimum 16 bytes)
        /// - `tweak`: Full tweak used during encryption (must be at least `kdf_tweak_length` bytes)
        ///
        /// Returns: `error.InputTooShort` if ciphertext is less than 16 bytes,
        ///          `error.TweakTooShort` if tweak is shorter than `kdf_tweak_length`,
        ///          `error.InvalidTweak` if the KDF-specific tweak format is invalid.
        pub fn decrypt(state: *const State, plaintext: []u8, ciphertext: []const u8, tweak: []const u8) !void {
            if (tweak.len < kdf_tweak_length) {
                return error.TweakTooShort;
            }

            const kdf_tweak = tweak[0..kdf_tweak_length];
            if (!validateKdfTweak(kdf_tweak)) {
                return error.InvalidTweak;
            }

            // Derive key from T0
            const derived_key = state.kdf.deriveKey(kdf_tweak);

            // Initialize HCTR2 with derived key and decrypt
            var hctr2 = Hctr2.init(derived_key);
            try hctr2.decrypt(plaintext, ciphertext, tweak[kdf_tweak_length..]);
        }

        /// Encrypt with split tweak: part for key derivation, part for HCTR2.
        ///
        /// This allows using a longer tweak by splitting it into:
        /// - `kdf_tweak`: Used for key derivation (must be `kdf_tweak_length` bytes)
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
            if (kdf_tweak.len < kdf_tweak_length) {
                return error.TweakTooShort;
            }
            if (kdf_tweak.len > kdf_tweak_length) {
                return error.TweakTooLong;
            }
            if (!validateKdfTweak(kdf_tweak)) {
                return error.InvalidTweak;
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
            if (kdf_tweak.len < kdf_tweak_length) {
                return error.TweakTooShort;
            }
            if (kdf_tweak.len > kdf_tweak_length) {
                return error.TweakTooLong;
            }
            if (!validateKdfTweak(kdf_tweak)) {
                return error.InvalidTweak;
            }

            const derived_key = state.kdf.deriveKey(kdf_tweak);
            var hctr2 = Hctr2.init(derived_key);
            try hctr2.decrypt(plaintext, ciphertext, hctr2_tweak);
        }

        fn validateKdfTweak(kdf_tweak: []const u8) bool {
            if (@hasDecl(Kdf, "validateTweak")) {
                return Kdf.validateTweak(kdf_tweak);
            }
            return kdf_tweak.len == kdf_tweak_length;
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
    const message = sequence(len);
    const t0 = tweak[0..16];
    const t_star = tweak[16..];
    var expected: [len]u8 = undefined;
    var output: [len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, hex);

    try cipher.encrypt(&output, &message, tweak);
    try std.testing.expectEqualSlices(u8, &expected, &output);
    try cipher.decrypt(&output, &expected, tweak);
    try std.testing.expectEqualSlices(u8, &message, &output);

    try cipher.encryptSplit(&output, &message, t0, t_star);
    try std.testing.expectEqualSlices(u8, &expected, &output);
    try cipher.decryptSplit(&output, &expected, t0, t_star);
    try std.testing.expectEqualSlices(u8, &message, &output);
}

test "HCTR2-TwKD known answers" {
    // Expected values were computed separately, following the paper.
    const cipher128 = Hctr2TwKD_128.init(sequence(16));
    const cipher256 = Hctr2TwKD_256.init(sequence(32));

    var tweak128 = sequence(20);
    tweak128[0] = 0x3f;
    var tweak256 = sequence(16) ++ "tail".*;
    tweak256[0] = 0x2a;

    try expectCiphertext(cipher128, &sequence(16), "69549f31b5a2e330c55a60989743ba99");
    try expectCiphertext(cipher128, &tweak128, "510ef09ca748a7405eaaad65d1e6cf90d0ab39236a40034bc0c4feb4cc611ede17");
    try expectCiphertext(cipher256, &sequence(16), "c397e7293e00d50bcaaec448b0c247a1");
    try expectCiphertext(cipher256, &tweak256, "4c8bfd522e0a059151ec81b8f341d2d9801446375cb59b25a195c1c55298c9e7b7e709538c33e9586b52f0fdbfa986b436148dc68c1017d2529627f684fbf9b5a3");
}

test "HCTR2-TwKD rejects bad input and tweaks" {
    const cipher = Hctr2TwKD_128.init(@splat(0));
    const input: [16]u8 = @splat(0x42);
    const tweak: [17]u8 = @splat(0);
    var output: [16]u8 = undefined;

    try std.testing.expectError(error.InputTooShort, cipher.encrypt(output[0..15], input[0..15], tweak[0..16]));
    try std.testing.expectError(error.TweakTooShort, cipher.encrypt(&output, &input, tweak[0..8]));
    try std.testing.expectError(error.TweakTooLong, cipher.encryptSplit(&output, &input, &tweak, ""));

    var bad_tweak = tweak;
    bad_tweak[0] = 0xc0;
    try std.testing.expectError(error.InvalidTweak, cipher.encrypt(&output, &input, &bad_tweak));
}
