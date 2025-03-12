# HCTR2 for Zig

An implementation of the [HCTR2](https://eprint.iacr.org/2021/1441.pdf) length-preserving encryption system.

HCTR2 is a tweakable super-permutation:
- It does not use a nonce, although it supports an optional tweak of any size.
- It does not add an authentication tag, but changing a single bit anywhere in the plaintext alters the entire ciphertext.

HCTR2 was originally designed for disk encryption, particularly for encrypting file names.

It also has many other use cases, including key wrapping and protocols such as LoRa, where nonces and authentication tags would be too large to authenticate individual messages.
