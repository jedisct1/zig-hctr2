# zig-hctr2

Pure Zig implementation of HCTR2, HCTR3, and format-preserving variants.

HCTR2 and HCTR3 are length-preserving tweakable wide-block encryption modes, while the format-preserving variants (HCTR2-FP and HCTR3-FP) preserve character sets with minimal expansion.

These modes are designed for full-disk encryption, filename encryption, and other applications where nonces and authentication tags would be impractical.

## What is HCTR2/HCTR3?

HCTR2 and HCTR3 are modern tweakable encryption modes that provide the following properties:

- Length-preserving: ciphertext is the same length as plaintext (no expansion)
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

Unlike standard HCTR2/HCTR3 which are strictly length-preserving, the format-preserving variants maintain the character set but have minimal expansion due to radix encoding requirements. HCTR2-FP and HCTR3-FP support any radix from 2 to 256. Pre-configured variants are provided for common radixes:

- Decimal (radix 10): useful for credit cards, IDs, phone numbers
- Hexadecimal (radix 16): useful for hex-encoded data
- Base64 (radix 64): useful for URL-safe encryption

Note that format-preserving modes have higher minimum message lengths (e.g., 39 bytes for decimal) compared to standard HCTR2/HCTR3 (16 bytes minimum).

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .hctr2 = .{
        .url = "https://github.com/yourusername/zig-hctr2/archive/refs/tags/v0.1.2.tar.gz",
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
    const key = [_]u8{0x00} ** 16;
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
    const key = [_]u8{0x00} ** 32;
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
    const key = [_]u8{0x00} ** 16;
    const cipher = hctr2.Hctr2Fp_128_Decimal.init(key);

    // Encrypt a credit card number (all digits remain digits)
    const plaintext = "1234567890123456789012345678901234567890"; // Min 39 bytes for decimal
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
    const key = [_]u8{0x00} ** 16;
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
- HCTR2-FP/HCTR3-FP: depends on radix (39 digits for decimal, 32 for hex, 22 for base64)

Messages shorter than the minimum will return `error.InputTooShort`.

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
