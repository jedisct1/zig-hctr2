# zig-hctr2

Pure Zig implementation of HCTR2, HCTR3, and their beyond-birthday-bound secure variants (CHCTR2, HCTR2-TwKD, HCTR2++), plus format-preserving variants.

HCTR2 and HCTR3 are length-preserving tweakable wide-block encryption modes. CHCTR2, HCTR2-TwKD and HCTR2++ are beyond-birthday-bound (BBB) secure variants: CHCTR2 and HCTR2-TwKD achieve approximately 85-bit security instead of HCTR2's 64-bit birthday-bound security, while HCTR2++ approaches full 128-bit security when tweaks are unique. The format-preserving variants (HCTR2-FP and HCTR3-FP) are also length-preserving and additionally preserve character sets (e.g., decimal digits remain decimal).

These modes are designed for full-disk encryption, filename encryption, and other applications where nonces and authentication tags would be impractical.

## What is HCTR2/HCTR3?

HCTR2 and HCTR3 are modern tweakable encryption modes that provide the following properties:

- Length-preserving: ciphertext is the same length as plaintext (no expansion beyond a minimum length)
- Wide-block: changing any single bit of plaintext affects the entire ciphertext
- Tweakable: supports a public tweak parameter for domain separation
- No authentication tag or nonce required
- Built entirely from standard primitives (AES, Polyval, SHA-256)

These modes are particularly useful when you need encryption but cannot afford the overhead of nonces or authentication tags, such as encrypting fixed-size disk sectors, filenames, or database fields.

## Which construction should I use?

### HCTR2

Use HCTR2 when you need:

- Fast, single-key encryption
- Good performance on modern hardware with AES-NI
- A simpler construction with fewer moving parts
- Compatibility with existing HCTR2 implementations

HCTR2 uses a single key and relies on Polyval for universal hashing and XCTR mode for the wide-block construction.

### HCTR3

Use HCTR3 when you need:

- Commitment security (resistance to key-manipulation attacks)
- Protection in scenarios where encryption keys might be known or compromised (cloud storage, message franking)
- Collision-resistant tweak processing for stronger domain separation
- Applications requiring both confidentiality and commitment properties

HCTR3 derives two keys from the input key and uses SHA-256 to hash tweaks before processing, providing collision resistance in known-key scenarios. This prevents commitment attacks (CMT-4) that break HCTR2 when adversaries can manipulate keys. HCTR3 employs ELK (Encrypted LFSR Keystream) mode with constant-time LFSR implementation instead of XCTR, providing additional security margins in constrained environments.

### CHCTR2 (Cascaded HCTR2)

Use CHCTR2 when you need:

- Beyond-birthday-bound security (~85-bit instead of ~64-bit)
- No restrictions on tweak usage
- Multi-user security guarantees
- Compatibility with NIST's BBB accordion mode requirements

CHCTR2 cascades HCTR2 twice with two independent keys, achieving 2n/3-bit multi-user security. The construction optimizes the middle hash layers: Z_{1,2} = H1(T,R) XOR H2(T,R). Cost is 2 block cipher calls + 3 field multiplications per block.

Reference: "Beyond-Birthday-Bound Security with HCTR2" (ASIACRYPT 2025)

### HCTR2-TwKD (Tweak-Based Key Derivation)

Use HCTR2-TwKD when you need:

- Beyond-birthday-bound security with minimal overhead
- Same performance as standard HCTR2
- Tweak-based key derivation (each unique tweak derives a unique key)
- Applications where the same tweak is not reused excessively

HCTR2-TwKD derives a fresh HCTR2 key from the first 126 bits of the tweak (T0) using the CENC construction, and passes the remaining tweak bytes (T*) to HCTR2. It achieves 2n/3-bit security when the number of encryptions per T0 is bounded by approximately 2^42. Cost per block is identical to HCTR2 (1 BC call + 2 field multiplications), with a small per-tweak overhead for key derivation.

Reference: "Beyond-Birthday-Bound Security with HCTR2" (ASIACRYPT 2025)

### HCTR2++ (Fresh Re-keying)

Use HCTR2++ when you need:

- The highest security level of the HCTR2 family, approaching O(2^128) with unique tweaks
- Graceful security degradation when tweaks are reused
- A construction built from a plain block cipher, at the price of speed

HCTR2++ keeps the Hash-Encrypt-Hash structure of HCTR2 but replaces every static block cipher call with Mennink's R3 fresh re-keying scheme and widens the universal hash function from 128 to 256 bits (POLYVAL-style polynomial evaluation over GF(2^256)). Every message block costs one AES key schedule, one AES call and two GF(2^256) multiplications, which makes it noticeably slower than HCTR2. The re-keyed block cipher calls are always AES-128, so the AES-256 variant only changes how subkeys are derived and still provides 128-bit effective strength.

Reference: "HCTR++: A Beyond Birthday Bound Secure HCTR2 Variant" (Ozturk, Kocak, Yayla)

### Format-Preserving Variants (HCTR2-FP and HCTR3-FP)

Use the format-preserving variants when you need:

- Encryption that preserves the character set (e.g., decimal digits remain decimal)
- Encrypted values in a specific radix (base-10, base-16, base-64, etc.)
- Filename encryption where certain characters are forbidden
- Database encryption where column types must be preserved

Like standard HCTR2/HCTR3, the format-preserving variants are length-preserving (no ciphertext expansion). They additionally maintain the character set by operating on digits in a specified radix. HCTR2-FP and HCTR3-FP support any radix from 2 to 256. Pre-configured variants are provided for common radixes:

- Decimal (radix 10): useful for credit cards, IDs, phone numbers
- Hexadecimal (radix 16): useful for hex-encoded data
- Base64 (radix 64): useful for URL-safe encryption

Note that format-preserving modes have higher minimum message lengths (e.g., 39 digits for decimal, 32 for hex, 22 for base64) compared to standard HCTR2/HCTR3 (16 bytes minimum).

### Common Radix Values

The following table shows common radix values for different use cases:

| Radix | Alphabet               | Use Cases                                | Notes                                  |
| ----- | ---------------------- | ---------------------------------------- | -------------------------------------- |
| 2     | `01`                   | Binary data, bit flags                   | Maximum length, minimal alphabet       |
| 4     | `ACGT` or `0123`       | DNA sequences, quaternary data           | Bioinformatics, compact binary         |
| 8     | `0-7`                  | Octal numbers                            | Unix file permissions, legacy systems  |
| 10    | `0-9`                  | Credit cards, phone numbers, numeric IDs | Pre-configured Human-readable numbers  |
| 16    | `0-9A-F`               | Hex strings, hashes, MAC addresses       | Pre-configured Common in computing     |
| 26    | `A-Z`                  | Alphabetic codes, license keys           | Case-insensitive text                  |
| 32    | `A-Z2-7`               | Base32 (RFC 4648), TOTP keys             | No ambiguous chars, 2FA tokens         |
| 32    | `0-9A-HJKMNP-TV-Z`     | Crockford Base32                         | Human-friendly, excludes I,L,O,U       |
| 36    | `0-9A-Z`               | Short IDs, URL shorteners                | Case-insensitive, compact              |
| 58    | `1-9A-HJ-NP-Za-km-z`   | Bitcoin/crypto addresses                 | No confusing chars (0,O,I,l removed)   |
| 62    | `0-9A-Za-z`            | URL shorteners, compact IDs              | Case-sensitive, very compact           |
| 63    | `0-9A-Za-z_`           | Programming identifiers                  | Alphanumeric + underscore              |
| 64    | `A-Za-z0-9+/`          | Base64 encoding, binary data             | Pre-configured Standard Base64         |
| 64    | `A-Za-z0-9-_`          | URL-safe Base64                          | Web-safe variant, no padding           |
| 66    | `A-Za-z0-9-._~`        | URL unreserved chars (RFC 3986)          | Safe for URLs without encoding         |
| 85    | ASCII printable        | Ascii85, binary encoding                 | Compact, printable characters          |
| 91    | ASCII printable subset | Base91                                   | Very compact binary encoding           |
| 95    | All printable ASCII    | Full printable character set             | Maximum compactness, may need escaping |

Filesystem-Safe Radixes:

- Radix 62-64: Safe across all major filesystems (Windows, Linux, macOS)
- Radix 66: URL unreserved characters, safe for both filenames and URLs
- Avoid characters: `/` (Unix/Linux), `\/:*?"<>|` (Windows), `:` (macOS Finder)

Common Pre-configured Variants:

- `Hctr2Fp_128_Decimal` / `Hctr3Fp_128_Decimal`: Radix 10
- `Hctr2Fp_128_Hex` / `Hctr3Fp_128_Hex`: Radix 16
- `Hctr2Fp_128_Base64` / `Hctr3Fp_128_Base64`: Radix 64
- AES-256 variants also available (e.g., `Hctr2Fp_256_Decimal`)

You can create custom radix variants for any use case:

```zig
// Choose radix 36 when identifiers are case-insensitive.
const Cipher36 = hctr2.Hctr2Fp(std.crypto.core.aes.Aes128, 36);

// Choose radix 58 for addresses that avoid lookalike characters.
const Cipher58 = hctr2.Hctr3Fp(std.crypto.core.aes.Aes256, std.crypto.hash.sha2.Sha256, 58);

// Choose radix 62 for compact, case-sensitive identifiers.
const Cipher62 = hctr2.Hctr2Fp(std.crypto.core.aes.Aes128, 62);
```

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .hctr2 = .{
        .url = "https://github.com/jedisct1/zig-hctr2/archive/refs/tags/0.1.9.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const hctr2 = b.dependency("hctr2", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("hctr2", hctr2.module("hctr2"));
```

## Usage Examples

### HCTR2 Encryption

```zig
const std = @import("std");
const hctr2 = @import("hctr2");

pub fn main() !void {
    // A real application should load this key from secure storage.
    const key: [16]u8 = @splat(0x00);
    const cipher = hctr2.Hctr2_128.init(key);

    // HCTR2 accepts messages of at least one 16-byte block.
    const plaintext = "Hello, World!!!!";
    const tweak = "sector-42";
    var ciphertext: [plaintext.len]u8 = undefined;

    try cipher.encrypt(&ciphertext, plaintext, &tweak);

    // Use the same tweak to recover the original message.
    var decrypted: [plaintext.len]u8 = undefined;
    try cipher.decrypt(&decrypted, &ciphertext, &tweak);
}
```

### HCTR3 Encryption

```zig
const hctr2 = @import("hctr2");

pub fn main() !void {
    // A real application should load this key from secure storage.
    const key: [32]u8 = @splat(0x00);
    const cipher = hctr2.Hctr3_256.init(key);

    const plaintext = "Sensitive data here!";
    const tweak = "database-record-123";
    var ciphertext: [plaintext.len]u8 = undefined;

    try cipher.encrypt(&ciphertext, plaintext, tweak);
    try cipher.decrypt(&plaintext_out, &ciphertext, tweak);
}
```

### CHCTR2 Encryption (Beyond-Birthday-Bound)

```zig
const hctr2 = @import("hctr2");

pub fn main() !void {
    // CHCTR2 keeps two AES-128 keys in this one 32-byte value.
    const key: [32]u8 = @splat(0x00);
    var cipher = hctr2.Chctr2_128.init(key);

    const plaintext = "BBB-secure data!";
    const tweak = "any-tweak-value";
    var ciphertext: [plaintext.len]u8 = undefined;

    try cipher.encrypt(&ciphertext, plaintext, tweak);

    var decrypted: [plaintext.len]u8 = undefined;
    try cipher.decrypt(&decrypted, &ciphertext, tweak);

    // This form is convenient when the two keys are stored separately.
    const key1: [16]u8 = @splat(0x01);
    const key2: [16]u8 = @splat(0x02);
    var cipher2 = hctr2.Chctr2_128.initSplit(key1, key2);
}
```

### HCTR2-TwKD Encryption (Tweak-Based Key Derivation)

```zig
const hctr2 = @import("hctr2");

pub fn main() !void {
    // The cipher derives a message key from this master key.
    const master_key: [16]u8 = @splat(0x00);
    const cipher = hctr2.Hctr2TwKD_128.init(master_key);

    const plaintext = "Sector data here";
    // The first 16 bytes select the derived key; the rest remains the HCTR2 tweak.
    // Its first byte must leave its top two bits clear.
    const tweak: [20]u8 = @splat(0x01);
    var ciphertext: [plaintext.len]u8 = undefined;

    // A distinct key-selection value produces a distinct derived key.
    try cipher.encrypt(&ciphertext, plaintext, tweak);

    var decrypted: [plaintext.len]u8 = undefined;
    try cipher.decrypt(&decrypted, &ciphertext, tweak);

    // Split mode leaves the HCTR2 portion free to be any length.
    const kdf_tweak: [16]u8 = @splat(0x02);
    const hctr2_tweak = "longer-tweak-passed-to-hctr2";
    try cipher.encryptSplit(&ciphertext, plaintext, &kdf_tweak, hctr2_tweak);
}
```

### HCTR2++ Encryption (Fresh Re-keying)

```zig
const hctr2 = @import("hctr2");

pub fn main() !void {
    const key: [16]u8 = @splat(0x00);
    var cipher = hctr2.Hctr2pp_128.init(key);

    const plaintext = "BBB-secure data!";
    // Give each message its own tweak for the strongest security guarantee.
    const tweak = "unique-tweak-value";
    var ciphertext: [plaintext.len]u8 = undefined;

    try cipher.encrypt(&ciphertext, plaintext, tweak);

    var decrypted: [plaintext.len]u8 = undefined;
    try cipher.decrypt(&decrypted, &ciphertext, tweak);
}
```

### Format-Preserving Encryption (Decimal)

```zig
const hctr2 = @import("hctr2");

pub fn main() !void {
    const key: [16]u8 = @splat(0x00);
    const cipher = hctr2.Hctr2Fp_128_Decimal.init(key);

    // Decimal mode keeps the result decimal and needs at least 39 digits.
    const plaintext = "1234567890123456789012345678901234567890";
    const tweak = "user-cc-field";
    var ciphertext: [plaintext.len]u8 = undefined;

    try cipher.encrypt(&ciphertext, plaintext, tweak);

    var decrypted: [plaintext.len]u8 = undefined;
    try cipher.decrypt(&decrypted, &ciphertext, tweak);
}
```

### Custom Radix Format-Preserving Encryption

```zig
const hctr2 = @import("hctr2");
const std = @import("std");

pub fn main() !void {
    // This radix covers decimal digits and lowercase letters.
    const Cipher = hctr2.Hctr2Fp(std.crypto.core.aes.Aes128, 36);
    const key: [16]u8 = @splat(0x00);
    const cipher = Cipher.init(key);

    // Keep inputs at or above the minimum length for this radix.
    const min_len = Cipher.first_block_length;
}
```

## Security Considerations

### No authentication

HCTR2 and HCTR3 provide confidentiality only, not authenticity. They do not detect tampering or forgery. If your threat model includes active attackers who can modify ciphertexts, you need additional authentication (e.g., HMAC, digital signatures) or should use an authenticated encryption mode like AES-GCM instead.

### Minimum message lengths

- HCTR2/HCTR3 and the BBB variants (CHCTR2, HCTR2-TwKD, HCTR2++): 16 bytes minimum
- HCTR2-FP/HCTR3-FP: depends on radix (e.g., 39 digits for radix-10, 32 digits for radix-16, 22 digits for radix-64)

Messages shorter than the minimum will return `error.InputTooShort`.

Important: Format-preserving modes are length-preserving (no expansion). Input length in digits equals output length in digits.

### Format-preserving first block encoding

In HCTR2-FP and HCTR3-FP, the first ciphertext block uses base-radix encoding, which may produce statistically distinguishable patterns. For example, in base-10 (decimal), the distribution of first-block digits may not appear uniformly random. However, the underlying encrypted data remains cryptographically secure—the encoding bias does not leak information about the plaintext.

### Key management

Standard key management practices apply:

- Use cryptographically secure random number generators for key generation
- Store keys securely (e.g., hardware security modules, encrypted key stores)
- Implement proper key rotation policies
- Never hardcode keys in source code

## Performance

Both HCTR2 and HCTR3 are designed to leverage AES-NI instructions on modern processors. Performance characteristics:

- HCTR2 is slightly faster due to simpler construction
- HCTR3 has higher security margins but slightly more overhead
- Format-preserving modes have additional computational cost from radix conversion
- Both scale well with message size (wide-block encryption is parallelized)

Run `zig build bench -Doptimize=ReleaseFast` to measure performance on your hardware.

## References

- [Length-preserving encryption with HCTR2](https://eprint.iacr.org/2021/1441) - Paul Crowley, Nathan Huckleberry, Eric Biggers (IACR ePrint Archive)
- [HCTR3](https://csrc.nist.gov/files/pubs/sp/800/197/iprd/docs/3_samvadini.pdf) - NIST SP 800-197 Workshop presentation
- [Beyond-Birthday-Bound Security with HCTR2](https://doi.org/10.1007/978-981-95-5018-0_1) - Chen, Y.L., et al. (ASIACRYPT 2025, LNCS 16245, pp. 3-34)
- HCTR++: A Beyond Birthday Bound Secure HCTR2 Variant - Kamil Ozturk, Onur Kocak, Oguz Yayla
