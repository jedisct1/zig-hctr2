# zig-hctr2

Pure Zig implementation of HCTR2, HCTR3, and format-preserving variants.

HCTR2 and HCTR3 are length-preserving tweakable wide-block encryption modes. The format-preserving variants (HCTR2-FP and HCTR3-FP) are also length-preserving and additionally preserve character sets (e.g., decimal digits remain decimal).

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
// Base-36 for case-insensitive alphanumeric identifiers
const Cipher36 = hctr2.Hctr2Fp(std.crypto.core.aes.Aes128, 36);

// Base-58 for cryptocurrency-style addresses
const Cipher58 = hctr2.Hctr3Fp(std.crypto.core.aes.Aes256, std.crypto.hash.sha2.Sha256, 58);

// Base-62 for compact URL shorteners
const Cipher62 = hctr2.Hctr2Fp(std.crypto.core.aes.Aes128, 62);
```

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .hctr2 = .{
        .url = "https://github.com/yourusername/zig-hctr2/archive/refs/tags/v0.1.3.tar.gz",
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
    // Initialize cipher with a 128-bit key
    const key: [16]u8 = @splat(0x00);
    const cipher = hctr2.Hctr2_128.init(key);

    // Encrypt a message
    const plaintext = "Hello, World!!!!"; // Minimum 16 bytes
    const tweak = "sector-42";
    var ciphertext: [plaintext.len]u8 = undefined;

    try cipher.encrypt(&ciphertext, plaintext, tweak);

    // Decrypt the message
    var decrypted: [plaintext.len]u8 = undefined;
    try cipher.decrypt(&decrypted, &ciphertext, tweak);
}
```

### HCTR3 Encryption

```zig
const hctr2 = @import("hctr2");

pub fn main() !void {
    // Initialize with AES-256
    const key: [32]u8 = @splat(0x00);
    const cipher = hctr2.Hctr3_256.init(key);

    const plaintext = "Sensitive data here!";
    const tweak = "database-record-123";
    var ciphertext: [plaintext.len]u8 = undefined;

    try cipher.encrypt(&ciphertext, plaintext, tweak);
    try cipher.decrypt(&plaintext_out, &ciphertext, tweak);
}
```

### Format-Preserving Encryption (Decimal)

```zig
const hctr2 = @import("hctr2");

pub fn main() !void {
    const key: [16]u8 = @splat(0x00);
    const cipher = hctr2.Hctr2Fp_128_Decimal.init(key);

    // Encrypt a credit card number (all digits remain digits)
    const plaintext = "1234567890123456789012345678901234567890"; // Min 39 digits for decimal
    const tweak = "user-cc-field";
    var ciphertext: [plaintext.len]u8 = undefined;

    try cipher.encrypt(&ciphertext, plaintext, tweak);
    // ciphertext contains only decimal digits

    var decrypted: [plaintext.len]u8 = undefined;
    try cipher.decrypt(&decrypted, &ciphertext, tweak);
}
```

### Custom Radix Format-Preserving Encryption

```zig
const hctr2 = @import("hctr2");
const std = @import("std");

pub fn main() !void {
    // Create a base-36 cipher (0-9, a-z)
    const Cipher = hctr2.Hctr2Fp(std.crypto.core.aes.Aes128, 36);
    const key: [16]u8 = @splat(0x00);
    const cipher = Cipher.init(key);

    // Minimum length depends on radix
    const min_len = Cipher.first_block_length;
    // ... use cipher
}
```

## Security Considerations

### No authentication

HCTR2 and HCTR3 provide confidentiality only, not authenticity. They do not detect tampering or forgery. If your threat model includes active attackers who can modify ciphertexts, you need additional authentication (e.g., HMAC, digital signatures) or should use an authenticated encryption mode like AES-GCM instead.

### Minimum message lengths

- HCTR2/HCTR3: 16 bytes minimum
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
