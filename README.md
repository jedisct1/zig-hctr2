# HCTR2 for Zig

A Zig implementation of [HCTR2](https://eprint.iacr.org/2021/1441.pdf) and HCTR3 length-preserving encryption systems.

## Features

- **Length-preserving encryption**: Ciphertext has the same length as plaintext
- **Tweakable cipher**: Supports optional tweaks of any size for domain separation
- **No nonce or authentication tag**: Designed for constrained environments
- **Wide-block cipher**: Encrypts messages of any size ≥ 16 bytes
- **Bit diffusion**: Changing a single bit in plaintext affects the entire ciphertext
- **Pure Zig implementation**: No external dependencies, uses only `std.crypto`

## Use Cases

Originally designed for disk encryption and filename encryption, HCTR2/HCTR3 are also suitable for:
- Key wrapping
- IoT protocols (e.g., LoRa) where nonces and authentication tags would be too large
- Any scenario requiring length-preserving encryption without expansion

## Installation

Requires Zig 0.14.0 or later.

### As a Zig Module

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .hctr2 = .{
        .url = "https://github.com/yourusername/zig-hctr2/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "...", // Use `zig fetch --save` to get the correct hash
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

## Usage

### HCTR2 Example

```zig
const std = @import("std");
const hctr2 = @import("hctr2");

// Create an HCTR2 instance with AES-256
const cipher = hctr2.Hctr2_256.init(key);

// Encrypt with an optional tweak
cipher.encrypt(&ciphertext, plaintext, tweak);

// Decrypt
cipher.decrypt(&plaintext, ciphertext, tweak);
```

### HCTR3 Example

```zig
const std = @import("std");
const hctr2 = @import("hctr2");

// HCTR3 with improved security
const cipher = hctr2.Hctr3_256.init(key);

// Use structured data as tweak
const tweak = "user@example.com|2024-01-01";
cipher.encrypt(&ciphertext, plaintext, tweak);
```

## API Reference

### Pre-configured Types

- `Hctr2_128` - HCTR2 with AES-128
- `Hctr2_256` - HCTR2 with AES-256
- `Hctr3_128` - HCTR3 with AES-128 and SHA-256
- `Hctr3_256` - HCTR3 with AES-256 and SHA-256

### Generic Types

- `Hctr2(comptime Aes)` - Generic HCTR2 with custom AES variant
- `Hctr3(comptime Aes, comptime Hash)` - Generic HCTR3 with custom primitives

### Methods

All cipher types provide:

- `init(key: [key_size]u8) Self` - Initialize with encryption key
- `encrypt(ciphertext: []u8, plaintext: []const u8, tweak: []const u8) void` - Encrypt data
- `decrypt(plaintext: []u8, ciphertext: []const u8, tweak: []const u8) void` - Decrypt data

## Building

```bash
# Build the library
zig build

# Run tests
zig build test

# Build and run examples
zig build-exe example_hctr3.zig
```

## Differences Between HCTR2 and HCTR3

**HCTR2**:
- Uses Polyval for universal hashing
- Single key for all operations
- Slightly faster

**HCTR3**:
- Adds SHA-256 hashing of tweaks
- Separate keys for encryption and authentication
- Enhanced security properties
- Recommended for new applications

## Security Considerations

- Messages must be at least 16 bytes (AES block size)
- The same key-tweak pair must never be used to encrypt different messages
- While length-preserving, these ciphers don't provide authentication - consider if your use case requires it
- For disk encryption, use unique tweaks (e.g., sector numbers) for each block
